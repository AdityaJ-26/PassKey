FROM ubuntu:latest AS build

ENV HOME=/root
# use the bash as shell inside container
SHELL ["/bin/bash", "-c"]

RUN apt update && apt install -y build-essential \
	cmake \
	gdb
