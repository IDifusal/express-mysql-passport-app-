const bcrypt = require('bcryptjs');
const helper = {};

helper.encryptPassword = async(password)=>{
    const salt = await bcrypt.genSalt(4);
    const hash = await bcrypt.hash(password,salt)
    return hash;
};

helper.matchPassword = async(password,savedPassowrd)=>{
    try {
        return await bcrypt.compare(password,savedPassowrd)
    } catch (error) {
        console.log(error)
    }
}
module.exports=helper;