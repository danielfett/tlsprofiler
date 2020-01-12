#!/bin/bash

docker-compose build
docker-compose run test_container
docker-compose down