const jwt = require('jsonwebtoken');

const getToken = require('./get-token')

const checkToken = async (req,res,next)=>{

    if(!req.headers.authorization){
        return res.status(401).json({message:'Acesso Negado!'})
    }

    const token = await getToken(req);

    if(!token){
        return res.status(401).json({message:"Acesso negado!"})
    }

    try{
        const verified = jwt.verify(token,'nossosecret')
        req.user = verified
        next()
    }catch(err){
        console.log(err)
        return res.status(400).json({message:'Token inválido!'})
    }
}

module.exports = checkToken