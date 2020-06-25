# Trellis Troubleshooting Tools

## Build

```
docker run -it --rm -v $HOME/.m2:/root/.m2 -v $PWD:/root/trellis-t3 -w /root/trellis-t3 maven:3.6.3-openjdk-11 mvn clean install

```

The OAR file can be located under `app/target`