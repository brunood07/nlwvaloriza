import { getCustomRepository } from "typeorm";

import { compare } from "bcryptjs";
import { sign } from "jsonwebtoken";

import { UsersRepositories } from "../repositories/UsersRepositories";



interface IAuthenticateRequest {
    email: string;
    password: string;
}

class AuthenticateUserService {

    async execute({email, password}: IAuthenticateRequest) {
        const usersRepositories = getCustomRepository(UsersRepositories);

        //verificar se email existe
        const user = await usersRepositories.findOne({ 
            email
        });

        if(!user) {
            throw new Error("Email/Password Incorrect")
        }
        //verificar se senha está correta

        // 123456 / 783644864-stfeqr981981
        const passwordMatch = await compare(password, user.password);
        
        if(!passwordMatch) {
            throw new Error("Email/Password Incorrect")
        }

        //gerar token
        const token = sign({
            email: user.email
        }, "0fae74dee0fc58bee00348079cc0c2d0", {
            subject: user.id,
            expiresIn: "1d"
        }
        );

        return token;
    }

}




export { AuthenticateUserService }