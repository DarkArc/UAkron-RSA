Implementation
  The program is composed of 6 classes:
    * Enryptor - Handles text encoding, as well as, encryption and decryption of said encoded text using the details in the provided KeyPair object
    * PairGenerator - Contains several functions used for creating the RSA keys
    * KeyPair - Holds the PublicKey and PrivateKey used for encryption
    * PrivateKey - A dedicated structure to hold n & d which compose the private key
    * PublicKey - A dedicated structure to hold n & e which compose the public key

Compilation
  Requirements:
    * JDK 7+
    * Maven [https://maven.apache.org/index.html]

  Compilation Steps:
    1) Go to the project directory via command line
    2) mvn compile package (Compiles the sources, and creates the jar)

Usage
  Steps:
    1) Go to the /target directory created by maven
    2) java -jar RSA-1.0-SNAPSHOT.jar (command arguments here)
