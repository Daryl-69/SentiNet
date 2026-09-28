const React=require('react');const {renderToStaticMarkup}=require('react-dom/server');const sharp=require('sharp');
const fa=require('react-icons/fa');
async function icon(name,color,size=256){const C=fa[name];if(!C)throw new Error('no icon '+name);
 const svg=renderToStaticMarkup(React.createElement(C,{color:'#'+color,size}));
 const buf=await sharp(Buffer.from(svg)).png().toBuffer();return 'image/png;base64,'+buf.toString('base64');}
module.exports={icon};
