# Axum server boilerplate

Boilerplate server project with ready-to-use auth implementations.
 - with credentials and verfification email
 - sign in with Google
 
To get started simply clone this repository. 

Optionally, if you have [task](https://github.com/go-task/task) installed, you can quickly init your project with it.
`task init` will replace all occurences of `axum-boilerplate` to whatever name is specified as a `PROJECT_NAME` variable in the Taskfile.

You can also use `task` to setup, develop, test and run your project locally.
To use [nexttest](https://github.com/nextest-rs/nextest) instead of build-in cargo test tool, swap uncommented and commented lines under `test` task.
To spin up your development database, you need to have [docker](https://www.docker.com/) installed, then just run `task up` and it will be ready to go.
There's more, to see full list of commands simply run `task --list`.
