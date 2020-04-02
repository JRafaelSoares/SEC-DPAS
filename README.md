# How to compile and test

First, in the base folder of the project, run:
    
    mvn install -DskipTests
    
Then, open a new terminal (while keeping the previous one open), go to the dpas-server folder and run:

    mvn compile exec:java
    
This will create a DPASServer instance. To test the server, in the first terminal, run:

    mvn test
    
To experiment with the functions directly, go to the dpas-client folder (with the server still open) and run:
    
    mvn compile exec:java