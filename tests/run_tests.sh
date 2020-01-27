#!/bin/bash
# You have to run this script from
# the root directory of this project.
# You can pass this script '--no-cache'
# to rebuild the test environment from
# scratch.

cd tests/certificates || exit
bash create_certs.sh
cd .. || exit

docker-compose build $1
docker-compose run test_container
docker-compose down
