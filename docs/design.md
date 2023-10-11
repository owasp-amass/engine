# Engine Design

Engine is an extensible library and recursive discovery / collection
service inspired by the depth of amass's collection capability.
It is distinctly different from amass in that it is not a CLI tool.
Rather, it is collection framework that will be used in future
versions of amass.

## Extensibility

First, `engine` is an _interface_. This means that you can write your own engine
to suite your needs. Engine is not an executable. Rather, it is a package meant to be embedded
or wrapped in a CLI or other service.

This project provides an in-memory Engine that uses channels for queueing.
The in-memory Engine serves as a reference implementation that can also be embedded
within local CLI tools.

Second, the `engine` is designed to send requests to implementations of the `Handler` _interface_.
Again, this was intentionally designed as an interface so that anyone can implement
Handlers with logic to meet their specific needs and extend the engine beyond our
initial vision.

`Handler`s implement the logic of the Engine. Some primary implementations include:

* `ScriptHandler` - Discovers Lua scripts that handle requests and execute the script
  with the request's details as input.
* `DBHandler` - Writes discovered `Asset`s and their `Relation`s to a database using
  [owasp-amass/asset-db](github.com/owasp-amass/asset-db).

The magic of `Handler`s is that they can also be wrapped by other one's through the use
of the `HandlerFunc` type. This allows us to decorate the inputs and outputs of each
`Handler` with additional features.
