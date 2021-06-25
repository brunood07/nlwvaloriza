# NLW Valoriza

Projeto realizado no NLW Together Trilha NodeJs

## Tecnologias Estudadas

- NodeJs
- Express
- SQLite
- Typescript
- JSON Web Tokens
- TypeORM

## Regras da Aplicação

- Cadastro de usuário

    - Não é permitido cadastrar mais de um usuário com o mesmo e-mail.

    - Não é permitido cadastrar usuário sem e-mail.

- Cadastro de Tag

    - Não é permitido cadastrar mais de uma Tag com o mesmo nome.

    - Não é permitido cadastrar Tag sem nome.

    - Não é permitido o cadastro por usuários que não sejam adiministradores.

- Cadastro de Elogios

    - Não é permitido um usuário cadastrar um elogio para si.

    - Não é Permitido cadastrar elogios para usuários inválidos.

    - O usuário precisa estar autenticado na aplicação.