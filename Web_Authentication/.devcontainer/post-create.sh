#!/bin/sh

dotnet tool install --global dotnet-ef --version 10.0.*
(cd App; dotnet restore; dotnet ef database update)
