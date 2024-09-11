const getToken = async (req)=>{
    const token = await req.headers.authorization.split(" ")[1]
    return token
}

module.exports = getToken