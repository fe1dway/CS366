# Encryption lab

In this lab, you will be implementing password hashing algorithms for a website. The files you will be editting include `App/Areas/Identity/{Iterative,PBDKF2,BCrypt,Argon2Id}Hasher.cs`. Feel free to look at the other files to get an idea how modern ASP.NET web apps are developed. If you want functionality shared between the four hashers, you can put it in `App/Areas/Identity/Utils.cs`. That file also contains an Encoding (ASCII) that you need to implement to convert from a salt and digest to bytes that can be written to the database.

## Running

* From the App folder run `dotnet run`. This will start the server.
* To view the sqlite database storing your users, use the visual studio command `SQLite: Open Database`. Then select the `app.db` file in the workspace directory. This will add a section on the left hand side of VSCode title `SQLITE EXPLORER`. From here you can click and look at the database tables.


## Testing

To aid you in testing your code, I've provided an `app-test.db` file that has properly encoded passwords for each of the four password hashing algorithms. Feel free to look at this file in the SQLite database explorer to see if your hashed passwords look correct. Additionally, you may copy this database to `app.db` to use it with your code and ensure that you can login with the following four users:

| Username  | Password   |
|-----------|------------|
| Iterative | Iterative  |
| PBKDF2    | PBKDF2     |
| BCrypt    | BCrypt     |
| Argon2id  | Argon2id   |
