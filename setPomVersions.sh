# With this command you can set a new version in all pom.xml files.
# Run it in the root folder of your project
#
# usage in Terminal:  ./setPomVersions.sh 1.0.0-SNAPSHOT
#
# after this mvn clean install and commit and push it to the develop branch
#
./mvnw org.codehaus.mojo:versions-maven-plugin:2.21.0:set -DnewVersion=$1 -DgenerateBackupPoms=false
