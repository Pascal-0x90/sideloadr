FROM ubuntu:latest

# Install packages
RUN apt update && apt -y install \
    mingw-w64 \
    python3 python3-dev python3-pip

# Install python poackages
RUN pip install poetry

# Copy in code and setup entrypoint
COPY . .
RUN poetry install

ENTRYPOINT [ "poetry", "run", "sideloadr" ]  