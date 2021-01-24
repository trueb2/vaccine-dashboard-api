# vaccine-dashboard-api
Actix + Diesel JSON REST API for vaccine-dashboard-ui for postgres backend

## User Authentication

There are publicly available create user and find user routes that take username + password and return a token for further use that is AUTH_SECRET dependent. 

The sample .env contains an example development environment. Actual deployments should set a secret AUTH_SECRET

## Health Routing

There is a health route exposed for integration with nginx style health checks with and without an authorization token.

## Districts

There is a route and model with metadata regarding abstract districts. 

* Districts are not protected against certain users. It is intended that they would be moderated.
* Districts statistics can be incremented by any authenticated user.
* All increments directly hit the database but should use some level of caching and/or separation of statistics.

## Build and Test

Restart the server after changes automatically

`systemfd --no-pid -s http::6969 -- cargo watch -x run`

Write tests and run them with 

`cargo test`

Configure database connections with dotenv docker with
* a running postgres container: `docker run --name dashboard-pg -e POSTGRES_PASSWORD=vaccine-dashboard-api -d -p 15432:5432 postgres`
* a DATABASE_URL in `.env`: `DATABASE_URL=postgresql://postgres:vaccine-dashboard-api@localhost:15432/test-dashboard`
* diesel_cli database configuration (with dotenv): `diesel database setup` or `diesel database reset`
* iterate on new migrations with `diesel migration run` to go one forward and `diesel database revert` to go back
