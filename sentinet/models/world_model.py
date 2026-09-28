"""The world model: learns P(S_{t+1} | S_<=t) over network states and rolls it forward.

    window t   ->  graph encoder (edge-weighted GraphSAGE, attention pooling)
                   + state-vector encoder                        -> e_t
    e_{t-L+1..t} -> causal temporal Transformer (band mask, ALiBi)-> c_t
    c_t         ->  posterior  q(z_t | c_t)                      (stochastic latent)
    (c_t, z_t)  ->  h_0 ;  h_{k+1} = GRU(z_k, h_k) ;  z_{k+1} ~ p(z | h_{k+1})   (latent dynamics)
    (z_k, h_k)  ->  decoders: next network state N(mu, sigma) ; ATT&CK stage ;
                   hazard of infiltration -> P(infiltration by step k)
    node emb + c_t -> per-host risk (who is likely to be hit next)

Rolling the latent dynamics K steps with S samples gives a distribution over
future trajectories; the share of mass on infiltration is the forecast.
"""
from __future__ import annotations

import math

import torch
import torch.nn as nn
import torch.nn.functional as F_


def mlp(i, h, o, drop=0.0):
    return nn.Sequential(nn.Linear(i, h), nn.GELU(), nn.Dropout(drop), nn.Linear(h, o))


class GraphEncoder(nn.Module):
    """Edge-weighted GraphSAGE (2 layers) over the per-window host graph."""

    def __init__(self, fn: int, d: int = 32):
        super().__init__()
        self.inp = nn.Linear(fn, d)
        self.self1, self.nb1 = nn.Linear(d, d), nn.Linear(d, d)
        self.self2, self.nb2 = nn.Linear(d, d), nn.Linear(d, d)
        self.att = nn.Sequential(nn.Linear(d, d), nn.Tanh(), nn.Linear(d, 1))
        self.d = d

    def forward(self, x, adj, mask):
        # x [B, N, Fn]  adj [B, N, N]  mask [B, N] bool
        m = mask.unsqueeze(-1).float()
        h = F_.gelu(self.inp(x)) * m
        A = adj + adj.transpose(-1, -2)
        deg = A.sum(-1, keepdim=True).clamp(min=1e-6)
        for s_l, n_l in ((self.self1, self.nb1), (self.self2, self.nb2)):
            nb = torch.bmm(A, h) / deg
            h = F_.gelu(s_l(h) + n_l(nb)) * m
        logits = self.att(h).squeeze(-1).masked_fill(~mask, -1e4)
        a = torch.softmax(logits, -1) * mask.float()
        a = a / a.sum(-1, keepdim=True).clamp(min=1e-6)
        g_att = (a.unsqueeze(-1) * h).sum(1)
        g_max = h.masked_fill(~mask.unsqueeze(-1), -1e4).max(1).values
        g_max = torch.where(mask.any(-1, keepdim=True), g_max, torch.zeros_like(g_max))
        return torch.cat([g_att, g_max], -1), h, a


class CausalBlock(nn.Module):
    def __init__(self, d, heads, drop=0.1):
        super().__init__()
        self.attn = nn.MultiheadAttention(d, heads, dropout=drop, batch_first=True)
        self.n1, self.n2 = nn.LayerNorm(d), nn.LayerNorm(d)
        self.ff = mlp(d, 2 * d, d, drop)

    def forward(self, x, bias, need_weights=False):
        y, w = self.attn(self.n1(x), self.n1(x), self.n1(x), attn_mask=bias, need_weights=need_weights,
                         average_attn_weights=True)
        x = x + y
        x = x + self.ff(self.n2(x))
        return x, w


def alibi_band_bias(T: int, L: int, heads: int, device) -> torch.Tensor:
    """Causal band mask (attend to at most L past positions incl. self) with
    ALiBi distance penalties -> [heads, T, T] additive float mask. Translation
    invariant, so training on (L+K)-long chunks matches inference on L."""
    i = torch.arange(T, device=device)
    dist = (i.view(-1, 1) - i.view(1, -1)).float()
    allowed = (dist >= 0) & (dist < L)
    slopes = torch.tensor([2 ** (-8 * (h + 1) / heads) for h in range(heads)], device=device)
    bias = -slopes.view(-1, 1, 1) * dist.clamp(min=0).unsqueeze(0)
    return bias.masked_fill(~allowed.unsqueeze(0), float("-inf"))


class WorldModel(nn.Module):
    def __init__(self, n_feat: int, n_node_feat: int, n_stages: int = 7, d: int = 64, dz: int = 32,
                 dg: int = 32, heads: int = 4, layers: int = 2, context: int = 30, horizon: int = 10,
                 drop: float = 0.1):
        super().__init__()
        self.cfg = dict(n_feat=n_feat, n_node_feat=n_node_feat, n_stages=n_stages, d=d, dz=dz, dg=dg,
                        heads=heads, layers=layers, context=context, horizon=horizon, drop=drop)
        self.genc = GraphEncoder(n_node_feat, dg)
        self.xenc = mlp(n_feat, d, d, drop)
        self.fuse = nn.Sequential(nn.Linear(d + 2 * dg, d), nn.GELU(), nn.LayerNorm(d))
        self.blocks = nn.ModuleList([CausalBlock(d, heads, drop) for _ in range(layers)])
        self.norm = nn.LayerNorm(d)
        self.post = nn.Linear(d, 2 * dz)
        self.h0 = nn.Linear(d + dz, d)
        self.gru = nn.GRUCell(dz, d)
        self.prior = mlp(d, d, 2 * dz)
        self.dec_x = mlp(dz + d, 2 * d, 2 * n_feat)
        self.dec_stage = mlp(dz + d, d, n_stages)
        self.dec_hazard = mlp(dz + d, d, 1)
        self.host = mlp(dg + d, d, 1)
        self.heads, self.context, self.horizon = heads, context, horizon
        self.dz = dz

    # ------------------------------------------------------------------ encode
    def encode_windows(self, X, node_X, adj, node_mask):
        """X [B, T, F], node_X [B, T, N, Fn], adj [B, T, N, N], node_mask [B, T, N]
        -> e [B, T, d], node_h [B, T, N, dg], node_att [B, T, N]"""
        B, T = X.shape[:2]
        N = node_X.shape[2]
        g, nh, na = self.genc(node_X.reshape(B * T, N, -1), adj.reshape(B * T, N, N), node_mask.reshape(B * T, N))
        e = self.fuse(torch.cat([self.xenc(X), g.view(B, T, -1)], -1))
        return e, nh.view(B, T, N, -1), na.view(B, T, N)

    def contextualise(self, e, pad_mask=None, need_weights=False):
        """e [B, T, d] -> c [B, T, d]; attention of the last layer [B, T, T]."""
        B, T, _ = e.shape
        bias = alibi_band_bias(T, self.context, self.heads, e.device)
        bias = bias.unsqueeze(0).expand(B, -1, -1, -1)
        if pad_mask is not None:  # [B, T] True = padding
            bias = bias.masked_fill(pad_mask.view(B, 1, 1, T), float("-inf"))
            # a padded position still attends to itself so no row is all -inf
            eye = torch.eye(T, dtype=torch.bool, device=e.device).view(1, 1, T, T)
            bias = bias.masked_fill(eye, 0.0)
        bias = bias.reshape(B * self.heads, T, T)
        x, w = e, None
        for i, blk in enumerate(self.blocks):
            x, w = blk(x, bias, need_weights=need_weights and i == len(self.blocks) - 1)
        return self.norm(x), w

    # ------------------------------------------------------------------ latent
    def posterior(self, c):
        mu, ls = self.post(c).chunk(2, -1)
        return mu, ls.clamp(-6, 2)

    def start(self, c, z):
        return torch.tanh(self.h0(torch.cat([c, z], -1)))

    def step(self, z, h):
        h = self.gru(z, h)
        mu, ls = self.prior(h).chunk(2, -1)
        return h, mu, ls.clamp(-6, 2)

    def decode(self, z, h):
        zh = torch.cat([z, h], -1)
        xm, xls = self.dec_x(zh).chunk(2, -1)
        return xm, xls.clamp(-5, 3), self.dec_stage(zh), self.dec_hazard(zh).squeeze(-1)

    def rollout(self, c, samples: int = 1, horizon: int | None = None, deterministic=False):
        """c [B, d] -> dict of per-step outputs, shapes [B, S, K, ...]."""
        K = horizon or self.horizon
        B = c.shape[0]
        mu, ls = self.posterior(c)
        cS = c.unsqueeze(1).expand(B, samples, -1).reshape(B * samples, -1)
        mu, ls = mu.repeat_interleave(samples, 0), ls.repeat_interleave(samples, 0)
        z = mu if deterministic else mu + torch.randn_like(mu) * ls.exp()
        h = self.start(cS, z)
        xs, stages, haz, zs = [], [], [], []
        for _ in range(K):
            h, pm, pls = self.step(z, h)
            z = pm if deterministic else pm + torch.randn_like(pm) * pls.exp()
            xm, xls, st, hz = self.decode(z, h)
            xs.append(xm), stages.append(st), haz.append(hz), zs.append((pm, pls))
        stack = lambda v: torch.stack(v, 1).view(B, samples, K, *v[0].shape[1:])  # noqa: E731
        hl = stack(haz)
        hazard = torch.sigmoid(hl)
        cum = 1 - torch.cumprod(1 - hazard, -1)
        return {"x_mean": stack(xs), "stage_logits": stack(stages), "hazard": hazard, "hazard_logit": hl,
                "p_infil_by_k": cum, "prior": zs}


    def host_risk(self, node_h, c):
        """node_h [B, N, dg], c [B, d] -> logits [B, N]"""
        N = node_h.shape[1]
        return self.host(torch.cat([node_h, c.unsqueeze(1).expand(-1, N, -1)], -1)).squeeze(-1)


def gaussian_nll(x, mean, log_std):
    return 0.5 * ((x - mean) / log_std.exp()) ** 2 + log_std + 0.5 * math.log(2 * math.pi)


def kl_normal(mu_q, ls_q, mu_p, ls_p):
    return (ls_p - ls_q + (torch.exp(2 * ls_q) + (mu_q - mu_p) ** 2) / (2 * torch.exp(2 * ls_p)) - 0.5).sum(-1)


def infil_log_odds(hazard_logit: torch.Tensor) -> torch.Tensor:
    """log-odds of P(infiltration within K) computed from the per-step hazard logits [..., K]
    without going through probabilities, so it does not saturate near 0 or 1:
    log(1 - P_none) = S = -sum softplus(h);  log-odds = log(1 - e^S) - S."""
    S = -F_.softplus(hazard_logit).sum(-1)
    return torch.log((-torch.expm1(S)).clamp(min=1e-30)) - S
