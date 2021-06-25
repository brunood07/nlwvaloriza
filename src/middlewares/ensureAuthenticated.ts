import { Request, Response, NextFunction } from "express";
import { verify } from "jsonwebtoken";

interface IPayLoad {
    sub: string;
}

export function ensureAuthenticated(request: Request, response: Response, next: NextFunction) {

    // Receber o token
    const authToken = request.headers.authorization
    
    // Validar se token está preenchido
    if(!authToken) {
        return response.status(401).end();
    }

    // pega o token bearer e separa o bearer e o token pelo espaço entre eles. posição 1 bearer, posição 2 o token.
    // no array na constante abaixo ele ignora o primeiro e salva o token
    const [,token] = authToken.split(" ")
    
    try{
        // Validar se token é válido
        const { sub } = verify( token, "0fae74dee0fc58bee00348079cc0c2d0") as IPayLoad;

        // Recuperar informações do usuário
        request.user_id = sub;

        return next();  
    }catch(err) {
        return response.status(401).end();
    }       
}