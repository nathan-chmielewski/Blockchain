/*--------------------------------------------------------

1. Name / Date:
Nathan Chmielewski / October 23, 2018

2. Java version used, if not the official version for the class:
java version "1.8.0_162"

3. Precise command-line compilation examples / instructions:
Compile java file using command-line instructions. Compile 2 times for inner classes:

> javac Blockchain.java
> javac Blockchain.java

4. Precise examples / instructions to run this program:
In separate shell windows, run the compiled files using command-line instructions
below. Launch the files in order: process 0, then process 1, then process 2
> java Blockchain 0
> java Blockchain 1
> java Blockchain 2

This was not tested across machines. It was tested using macOS terminal, all
running on local machine.

5. List of files needed for running the program.
- Blockchain.java
- BlockInput0.txt
- BlockInput1.txt
- BlockInput2.txt

5. Notes:
- The program is limited to 3 processes (hardcoded in numProcesses variable)
- The program is limited to the three files above (using switch statement and Process ID)
- The program does not implement the commands as specified in the assignment instructions,
  therefore, user input results in no behavior by any of the three processes.
- There are many ways this does not conform to a real blockchain, but offers
  a rough execution of how the basic structure of blockchain technology works.
- For example, block data is stored in multiple places, such as an array, as
  as well as an XML ledger. Nothing is encrypted, and all data can be changed
  at at any time. This clearly raises privacy and security concerns meant to be
  solved by the use of blockchain.
- All processes run continuously until shell is terminated.

- The program makes use of utility code provided by Clark Elliott, including
> BlockH.java
> BlockInputE.java
> WorkA.java

And the following web sources:
http://www.java2s.com/Code/Java/Security/SignatureSignAndVerify.htm
https://www.mkyong.com/java/java-digital-signatures-example/ (not so clear)
https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
https://www.programcreek.com/java-api-examples/index.php?api=java.security.SecureRandom
https://www.mkyong.com/java/java-sha-hashing-example/
https://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object

XML validator:
https://www.w3schools.com/xml/xml_validator.asp

XML / Object conversion:
https://www.mkyong.com/java/jaxb-hello-world-example/
Reading lines and tokens from a file:
http://www.fredosaurus.com/notes-java/data/strings/96string_examples/example_stringToArray.html

XML validator:
https://www.w3schools.com/xml/xml_validator.asp

XML / Object conversion:
https://www.mkyong.com/java/jaxb-hello-world-example/

Work:
https://www.quickprogrammingtips.com/java/how-to-generate-sha256-hash-in-java.html  @author JJ
https://dzone.com/articles/generate-random-alpha-numeric  by Kunal Bhatia  ·  Aug. 09, 12 · Java Zone

with many modifications and my own commentary throughout all of the code.
----------------------------------------------------------*/

import java.util.*;
import java.io.*;
import java.net.*;
import java.util.concurrent.*;

// NC: Imports
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import java.security.Signature;
import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;

// Block Record with fields to hold all health data from files, as well as
// block data to build blockchain  
@XmlRootElement
class BlockRecord implements Comparable<BlockRecord> {
  String blockNum;
  String SHA256String;
  String SignedSHA256;
  String BlockID;
  String VerificationProcessID;
  String CreatingProcess;
  String Fname;
  String Lname;
  String SSNum;
  String DOB;
  String Diag;
  String Treat;
  String Rx;
  // Additional fields added - timestamp, signed blockID, seed, and previousHash
  String previousHash;
  String dateCreated;
  String signedBlockID;
  String seed;

  // Getter and setter methods for all block record fields
  public String getASHA256String() {return SHA256String;}
  @XmlElement
  public void setASHA256String(String SH){this.SHA256String = SH;}

  public String getASignedSHA256() {return SignedSHA256;}
  @XmlElement
  public void setASignedSHA256(String SH){this.SignedSHA256 = SH;}

  public String getACreatingProcess() {return CreatingProcess;}
  @XmlElement
  public void setACreatingProcess(String CP){this.CreatingProcess = CP;}

  public String getAVerificationProcessID() {return VerificationProcessID;}
  @XmlElement
  public void setAVerificationProcessID(String VID){this.VerificationProcessID = VID;}

  public String getABlockID() {return BlockID;}
  @XmlElement
  public void setABlockID(String BID){this.BlockID = BID;}

  public String getFSSNum() {return SSNum;}
  @XmlElement
  public void setFSSNum(String SS){this.SSNum = SS;}

  public String getFFname() {return Fname;}
  @XmlElement
  public void setFFname(String FN){this.Fname = FN;}

  public String getFLname() {return Lname;}
  @XmlElement
  public void setFLname(String LN){this.Lname = LN;}

  public String getFDOB() {return DOB;}
  @XmlElement
  public void setFDOB(String DOB){this.DOB = DOB;}

  public String getGDiag() {return Diag;}
  @XmlElement
  public void setGDiag(String d){this.Diag = d;}

  public String getGTreat() {return Treat;}
  @XmlElement
  public void setGTreat(String t){this.Treat = t;}

  public String getGRx() {return Rx;}
  @XmlElement
  public void setGRx(String rx){this.Rx = rx;}

  // The below functions were added for the additional fields created
  public String getPreviousHash() {return previousHash; }
  @XmlElement
  public void setPreviousHash(String ph){this.previousHash = ph; }

  public String getDateCreated() { return dateCreated; }
  @XmlElement
  public void setDateCreated(String date) { this.dateCreated = date; }

  public String getSignedBlockID() { return signedBlockID; }

  public void setSignedBlockID(String sid) { this.signedBlockID = sid; }

  public String getBlockNum() { return blockNum; }

  public void setBlockNum(String n) { this.blockNum = n; }

  public String getSeed() { return seed; }

  public void setSeed(String s) { this.seed = s; }

  // CompareTo method provides comparator to sort queue of block records by
  // date created timestamp field
  public int compareTo(BlockRecord br) {
    return this.dateCreated.compareTo(br.dateCreated);
  }

}

// Would normally keep a process block for each process in the multicast group:
class ProcessBlock {
  int processID;
  PublicKey pubKey;
  int port;
  String IPAddress;

  ProcessBlock(int pid, PublicKey pk, int p, String ipa) {
    processID = pid;
    pubKey = pk;
    port = p;
    IPAddress = ipa;
  }
}

// Ports class sets base port numbers for PublicKeyServer, UnverifiedBlockServer
// and BlockChainServer. Process number is added to port number for each
// additional process in the multicast group.
class Ports {
  public static int KeyServerPortBase = 4710;
  public static int UnverifiedBlockServerPortBase = 4820;
  public static int BlockchainServerPortBase = 4930;
  public static int ServerAvailablePortBase = 5040;
  public static int LedgerPortBase = 5150;

  public static int KeyServerPort;
  public static int UnverifiedBlockServerPort;
  public static int BlockchainServerPort;
  public static int ServerAvailablePort;
  public static int LedgerPort;

  public void setPorts(){
    KeyServerPort = KeyServerPortBase + Blockchain.PID;
    UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + Blockchain.PID;
    BlockchainServerPort = BlockchainServerPortBase + Blockchain.PID;
    ServerAvailablePort = ServerAvailablePortBase + Blockchain.PID;
    LedgerPort = LedgerPortBase = Blockchain.PID;
  }
}

// Worker thread to process incoming public key data from all processes and
// store in ProcessBlock array;
class PublicKeyWorker extends Thread { // Class definition
  Socket sock;
  // Process block array to store processes in multicast group
  ProcessBlock[] processBlocks;
  // Constructor to store socket and process block data
  PublicKeyWorker (Socket s, ProcessBlock[] pb) {
    sock = s;
    processBlocks = pb;

  }
  public void run() {

    try {
      ObjectInputStream ois = new ObjectInputStream(sock.getInputStream());
      // Read in Process ID and store in variable
      int tempPID = ois.readInt();
      // Read in process's public key
      PublicKey publicKey = (PublicKey)ois.readObject();
      System.out.println("Received Process " + tempPID + "'s Public Key.");

      // Instantiate ProcessBlock with Process ID, public key, port number and server
      processBlocks[tempPID] = new ProcessBlock(tempPID, publicKey, (Ports.KeyServerPortBase + tempPID), "localhost");
      // For testing purposes, print Process block contents
      // System.out.println("ProcessBlock [" + tempPID + "]");
      // System.out.println("PID: " + processBlocks[tempPID].processID);
      // System.out.println("Public Key: " + processBlocks[tempPID].pubKey);
      // System.out.println("Port: " + processBlocks[tempPID].port);
      // System.out.println("Server: " + processBlocks[tempPID].IPAddress);
      sock.close();
    } catch (Exception x){ x.printStackTrace(); }
  }
}

// Server to process incoming public keys sent from all processes
class PublicKeyServer implements Runnable {
  // One block to store info for each process.
  public ProcessBlock[] processBlocks;

  PublicKeyServer(ProcessBlock[] pb) {
    processBlocks = pb;
  }

  public void run(){
    int q_len = 6;
    Socket socket;
    System.out.println("Starting Public Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
    try {
      // Open server socket and accept incoming socket connections from all
      // processes to store public keys
      ServerSocket serverSocket = new ServerSocket(Ports.KeyServerPort, q_len);
      while (true) {
        socket = serverSocket.accept();
        Thread.sleep(500);
        new PublicKeyWorker(socket, processBlocks).start();
      }
    } catch (Exception ioe) {System.out.println(ioe);}
  }
}

// Server to open socket to accept connection to spawn worker thread to process
// unverified block data as XML.
class UnverifiedBlockServer implements Runnable {
  // Priority queue to hold unverified block data in order by timestamp
  BlockingQueue<BlockRecord> queue;
  UnverifiedBlockServer(BlockingQueue<BlockRecord> queue) {
    this.queue = queue;
  }

  // Worker thread spawns to store unverified blocks sent as xml data from all
  // processes. Blocks are stored in the priority queue in order by timestamp
  // and will be taken out of queue by consumer thread.
  class UnverifiedBlockWorker extends Thread { // Class definition
    Socket sock; // Class member, socket, local to Worker.
    UnverifiedBlockWorker (Socket s) {sock = s;} // Constructor, assign arg s to local sock
    public void run(){
      try{

        ObjectInputStream ois = new ObjectInputStream(sock.getInputStream());
        String xmlData = (String)ois.readObject();
        String XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";

        // For testing purposes, print XML to console
        // System.out.println("XML Block: \n" + xmlData);

        // Unmarshal XML block back to BlockRecord object to store in the queue
        JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
        Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
        StringReader xmlReader = new StringReader(xmlData);

        BlockRecord xmlToBlockRecord = (BlockRecord)jaxbUnmarshaller.unmarshal(xmlReader);

        // For testing purposes, print a field of the BlockRecord that was
        // created from the unmarashalled XML data sent to the process
        // System.out.println("XML data unmarshalled to BlockRecord object.");
        // System.out.println("XMLToBlockRecord Name: " + xmlToBlockRecord.getFFname());

        // Put Block Record object in priority queue for consumer to take.
        queue.put(xmlToBlockRecord);

        // Print for testing purposes to show all BlockRecords in the queue are
        // sorted by timestamp, and collisions are resolved by process number
        //   BlockRecord brTest = queue.poll();
        //   while(brTest != null) {
        //     System.out.println("brTest timestamp: " + brTest.getDateCreated());
        //     brTest = queue.poll();
        //   }
        // }

        sock.close();
      } catch (Exception x){x.printStackTrace();}
    }
  }

  public void run(){
    int q_len = 6;
    Socket socket;
    System.out.println("Starting the Unverified Block Server input thread using " +
    Integer.toString(Ports.UnverifiedBlockServerPort));
    try {
      // Start server to accept a socket connection and spawn a worker thread
      // to process incoming XML block record data
      ServerSocket serverSocket = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
      while (true) {
        socket = serverSocket.accept();
        new UnverifiedBlockWorker(socket).start();
      }
    }catch (IOException ioe) {System.out.println(ioe);}
  }
}

// Consumer thread accesses priority queue, takes the block record out that has
// the earliest timestamp, and hashes a piece of the blockdata with the previous
// block's hash. Then begins to perform work by generating a seed, appending
// the seed to the hash, and performing work based on some byte data from the
// hash. Once the puzzle is solved, the block is verified, and added to the ledger.
class UnverifiedBlockConsumer implements Runnable {
  BlockingQueue<BlockRecord> queue;
  private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  KeyPair keyPair;
  ProcessBlock[] processBlocks;

  // int PID;
  UnverifiedBlockConsumer(BlockingQueue<BlockRecord> queue, KeyPair kp, ProcessBlock[] pb){
    this.queue = queue; // Constructor binds our prioirty queue to the local variable.
    this.keyPair = kp;
    this.processBlocks = pb;
  }

  public static String randomAlphaNumeric(int count) {
    StringBuilder builder = new StringBuilder();
    while (count-- != 0) {
      int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
      builder.append(ALPHA_NUMERIC_STRING.charAt(character));
    }
    return builder.toString();
  }

  public void run() {
    // Variable to store unverified block data
    BlockRecord uvBlockData;

    System.out.println("Starting the Unverified Block Priority Queue Consumer thread.\n");

    try{
      while(true) { // Consume from the incoming queue. Do the work to verify. Mulitcast new blockchain
        System.out.println("Priority queue empty, waiting for more unverified blocks...");
        uvBlockData = queue.take(); // Will blocked-wait on empty queue
        // System.out.println("Consumer got unverified: " + data);

        System.out.println("Consumer has unmarshalled unverified block: " + uvBlockData.getFFname());

        // Verify the signed blockID using the public key of the creating process.
        // Decode the signed blockID using Base64 decoder from string into bytes.
        // Pass decoded bytes, creating process's public key, and unsigned blockID
        // bytes to verifySig method to test verification.
        int creatingProcess = Integer.parseInt(uvBlockData.getACreatingProcess());
        byte[] testSignature = Base64.getDecoder().decode(uvBlockData.getSignedBlockID());
        boolean verified = Blockchain.verifySig(uvBlockData.getABlockID().getBytes(), processBlocks[creatingProcess].pubKey, testSignature);
        System.out.println("Has the BlockID been verified: " + verified + "\n");

        // insert a sequential blockNum that is one greater than the most recent
        // block in the current blockchain.
        uvBlockData.setBlockNum(Integer.toString(Blockchain.nextBlockIndex));

        // Insert the verifying process's ID into the unverified block.
        uvBlockData.setAVerificationProcessID(Integer.toString(Blockchain.PID));

        // Concatenate the SHA-256 hash from the previous block in the
        // blockchain to some block data from the verified block, to produce
        // UB string.
        // In this program, I hashed the block ID with the previous block's
        // SHA-256 hash. In practice some unique blockdata of the unverified
        // block should be hashed with the previous block's SHA-256 hash.

        String UB = uvBlockData.getABlockID() + Blockchain.blockList.get(Blockchain.nextBlockIndex-1).getASHA256String();
        String UBSeed = "";

        // While loop will repeatedly generate a random seed string, append it
        // to string UB, hash the string, get the left-most 16 bits, generate
        // an unsigned int, and perform "work". If the int is <20000, the
        // puzzle is "solved" and the block can be verified.
        System.out.println("Working to solve puzzle...");
        while(true) {
          // Sleep to keep things running smoothly...
          try { Thread.sleep(250); } catch(Exception e){ e.printStackTrace(); }
          // Generate a random string to append to UB.
          String seed = randomAlphaNumeric(8);
          UBSeed = UB + seed;
          uvBlockData.setSeed(seed);
          // Produce an SHA-256 hash of the seed-updated UB and
          // Hash UB string and get the bytes value
          MessageDigest md = MessageDigest.getInstance("SHA-256");
          byte[] UBHashBytes = md.digest(UBSeed.getBytes("UTF-8"));
          // Turn the bytes of the hash into a hex value string
          String hexString = DatatypeConverter.printHexBinary(UBHashBytes);
          // Get left-most 16 bits of the hex. Value will be between 0 (0000)
          // and 65535 (FFFF)
          int workNumber = Integer.parseInt(hexString.substring(0,4),16);
          // For testing purposes, print work number generated
          // System.out.println("First 16 bits " + hexString.substring(0,4) +": " + workNumber + "\n");

          // Check the block ID to see if it matches the most recent block
          // added to the blockchain. If true, break out of the while loop.
          // This unverified block has already been verified and added to the ledger.
          if(uvBlockData.getABlockID().equals(Blockchain.blockList.get(Blockchain.nextBlockIndex-1).getABlockID())) {
            System.out.println("Duplicate. Unverified block has been added to the ledger by another process.");
            break;
          }
          // if the hex value is below 20000 (4E20) when parsed as an unsigned
          // int (workNumber), the "work" puzzle is solved
          if (workNumber < 20000) {
            System.out.println("Puzzle solved! Block verified.");
            // System.out.println("The seed was: " + seed);
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < UBHashBytes.length; i++) {
              sb.append(Integer.toString((UBHashBytes[i] & 0xff) + 0x100, 16).substring(1));
            }

            String SHA256String = sb.toString();
            uvBlockData.setASHA256String(SHA256String);
            // Sign SHA 256 string and store in block data
            byte[] digitalSignatureSHA = Blockchain.signData(SHA256String.getBytes(), keyPair.getPrivate());
            String SignedSHA256 = Base64.getEncoder().encodeToString(digitalSignatureSHA);
            uvBlockData.setASignedSHA256(SignedSHA256);

            // Marshall the newly verified blockchain to XML and call multicast
            // method to send to all processes in multicast group to add the
            // block to the ledger so that all processes move on to begin
            // attempting to verify the next block.

            // JAXB instance and Marshaller to convert java object to XML
            JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
            // StringWriter object to write BlockRecord as XML to StringWriter
            StringWriter stringWriter = new StringWriter();
            jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            // Marshall BlockRecord to XML
            jaxbMarshaller.marshal(uvBlockData, stringWriter);
            // XML BlockRecord string
            String xmlBlock = stringWriter.toString();
            // Call method to send xml data of verified block record to all processes
            Blockchain.MultiSendBlockchain(xmlBlock);
            break;
          }
        }
        // Sleep to keep things running smoothly...
        Thread.sleep(1000);
      }
    } catch (Exception e) {System.out.println(e);}
  }
}


// Class to get verified block xml data, unmarshal the block, add it to a block
// array that each process uses to keep track of what blocks are in the ledger.
// If Process 0, create and write to BlockchainLedger.xml file.
class BlockchainWorker extends Thread { // Class definition
  Socket sock; // Class member, socket, local to Worker.
  BlockchainWorker (Socket s) {sock = s;} // Constructor, assign arg s to local sock
  public void run(){
    try {
      ObjectInputStream ois = new ObjectInputStream(sock.getInputStream());
      // Get verified block marshalled as XML from sending process
      String xmlData = (String)ois.readObject();
      // Print verified XML block for testing purposes
      // System.out.println("XML Block: \n" + xmlBlock);

      // unmarshal XML block back to java BlockRecord object
      JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
      Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
      StringReader xmlReader = new StringReader(xmlData);
      BlockRecord xmlToBlockRecord = (BlockRecord)jaxbUnmarshaller.unmarshal(xmlReader);

      // Add to block array that holds verified blocks to perform check.
      Blockchain.blockList.add(xmlToBlockRecord);
      Blockchain.nextBlockIndex++;
      System.out.println("--NEW BLOCKCHAIN--");
      System.out.println("Verified blocks:");

      // For testing purposes, print list of verified block record names each
      // time one is added.
      for(int n = 0; n < Blockchain.blockList.size(); n++) {
        System.out.println(Blockchain.blockList.get(n).getFFname() + " " + Blockchain.blockList.get(n).getFLname());
      }

      // If Process 1, create BlockchainLedger xml file. In practice, this should
      // be built dynamically as processes in the multicast group verify each
      // block. For the purposes of this application, the file is completely
      // rewritten every time a block is verified and added to the ledger.
      // The written file will be available in the directory that the application runs.
      if(Blockchain.PID == 0) {
        String XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
        System.out.println("Writing XML file...");
        File ledger = new File("BlockchainLedger.xml");
        FileWriter fw = new FileWriter(ledger);
        StringBuffer sb = new StringBuffer();
        String xmlBlock = "";
        String xmlBlockToWrite = "";

        for(int n = 0; n < Blockchain.blockList.size(); n++) {
          // System.out.println(Blockchain.blockArray[n].getFFname());
          Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
          // StringWriter object to write BlockRecord as XML to StringWriter
          StringWriter stringWriter = new StringWriter();
          jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
          // Marshall BlockRecord to XML, write to stringWriter object
          jaxbMarshaller.marshal(Blockchain.blockList.get(n), stringWriter);
          // XML BlockRecord string
          xmlBlock = stringWriter.toString();
          sb.append(xmlBlock.replace(XMLHeader, ""));
          // Format the XML data when printed or written to file
          jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        }
        String BlockchainLedger = "<BlockLedger>" + sb.toString() + "</BlockLedger>";
        fw.write(BlockchainLedger);
        fw.flush();
        sb.delete(0, sb.length());
        try { Thread.sleep(500); } catch(Exception e){ e.printStackTrace(); } // Wait for servers to start.
        System.out.println("Finished writing file.");
      }
      sock.close();
    } catch (Exception x){ x.printStackTrace();}
  }
}

class LedgerWorker extends Thread {
  String BlockchainLedger;
  public void run(){
    try {
      ObjectInputStream ois = new ObjectInputStream(sock.getInputStream());
      BlockchainLedger = (String)ois.readObject();
}


class LedgerServer implements Runnable {

  public void run(){
    int q_len = 6;
    Socket socket;
    System.out.println("Starting Ledger Server input thread using " + Integer.toString(Ports.LedgerPort));
    try {
      // Open server socket and accept incoming socket connections from all
      // processes to store public keys
      ServerSocket serverSocket = new ServerSocket(Ports.LedgerPort, q_len);
      while (true) {
        socket = serverSocket.accept();
        Thread.sleep(500);
        new LedgerWorker(socket).start();
      }
    } catch (Exception ioe) {System.out.println(ioe);}
  }
}

// Server to open a connection to accept socket connection from all processes
// to store verified blocks and add to Blockchain Ledger.
class BlockchainServer implements Runnable {
  public void run(){
    int q_len = 6;
    Socket sock;
    System.out.println("Starting the blockchain server input thread using " + Integer.toString(Ports.BlockchainServerPort));
    try{
      ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);
      while (true) {
        sock = servsock.accept();
        new BlockchainWorker (sock).start();
      }
    }catch (IOException ioe) {System.out.println(ioe);}
  }
}

// Dummy server for Process 2 to start so that, when started, all other
// processes will begin executing the blockchain program.
class ServerAvailable implements Runnable {
  public void run(){
    Socket sock;
    System.out.println("Process 2 started.");
    try{
      ServerSocket servsock = new ServerSocket(Ports.ServerAvailablePort, 0);
      while (true) {
      }
    }catch (IOException ioe) {System.out.println(ioe);}
  }
}

// Class Blockchain for BlockChain contains multicast methods, signature methods, and
// main method that begins every server thread. Blockchain class holds variables
// containing the server name, local block array to keep track of verified
// blocks in the ledger, local process ID, and key pair.
public class Blockchain {
  static String serverName = "localhost";
  // static BlockRecord[] blockArray = new BlockRecord[20];
  static ArrayList<BlockRecord> blockList = new ArrayList<BlockRecord>();
  static int nextBlockIndex = 1;
  static String blockchain = "[First block]";
  static int numProcesses = 3;
  static int PID = 0;
  static ProcessBlock[] processBlocks = new ProcessBlock[3];
  static KeyPair processKeyPair;

  // Method to sign BlockRecord's BlockID with the creating process's private key
  // and to sign the SHA256-hash of the data. The SHA-hash of the data is not
  // implemented in this program.
  public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
    Signature signer = Signature.getInstance("SHA1withRSA");
    signer.initSign(key);
    signer.update(data);
    return (signer.sign());
  }

  // Used by the UVConsumer thread to verify a BlockRecord's blockID with the
  // PublicKey of the creating process
  public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
    Signature signer = Signature.getInstance("SHA1withRSA");
    signer.initVerify(key);
    signer.update(data);

    return (signer.verify(sig));
  }

  // Method to send process's public key to all processes in the multicast group.
  public static void MultiSendPublicKey(PublicKey publicKey) {
    Socket socket;
    ObjectOutputStream oos;

    // Send process's PublicKey passed in as parameter to all processes
    try {
      System.out.println("Multicasting Process ID and Process Public Key.");
      for(int i = 0; i < Blockchain.numProcesses; i++) {
        socket = new Socket(serverName, (Ports.KeyServerPortBase + i));
        oos = new ObjectOutputStream(socket.getOutputStream());
        // Send process number through socket to all other processes
        oos.writeInt(PID);
        // Send public key through socket to all other processes
        oos.writeObject(publicKey);
        socket.close();
      }
    } catch (Exception x) { x.printStackTrace (); }
  }
/*
  public static void MultiSendLedger(String BlockchainLedger) {
    Socket socket;
    ObjectOutputStream oos;
    try {
      System.out.println("Multicasting Process ID and Process Public Key.");
      for(int i = 0; i < Blockchain.numProcesses; i++) {
        socket = new Socket(serverName, (Ports.KeyServerPortBase + i));
        oos = new ObjectOutputStream(socket.getOutputStream());
        // Send process number through socket to all other processes
        oos.writeInt(PID);
        // Send public key through socket to all other processes
        oos.writeObject(publicKey);
        socket.close();
      }
    } catch (Exception x) { x.printStackTrace (); }
  }
*/
  public static void MultiSendBlockchain(String xmlBlock) {
    Socket socket;
    ObjectOutputStream oos;

    try {
      System.out.println("Sending verified blockchain to all processes.");
      for(int i = 0; i < Blockchain.numProcesses; i++) {
        socket = new Socket(serverName, (Ports.BlockchainServerPortBase + i));
        oos = new ObjectOutputStream(socket.getOutputStream());

        oos.writeObject(xmlBlock);
        socket.close();
      }
    } catch (Exception x) { x.printStackTrace (); }
  }

  // METHOD FROM ELLIOTT'S BlockH.java TO GENERATE PUBLIC AND PRIVATE KEY PAIR
  // FOR THE PROCESS
  public static KeyPair generateKeyPair(long seed) throws Exception {
    KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
    SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rng.setSeed(seed);
    keyGenerator.initialize(1024, rng);

    return (keyGenerator.generateKeyPair());
  }

  public static void MultiSendUVBlock(KeyPair keyPair) {
    Socket socket;
    ObjectOutputStream oos;

    String fileName;

    final int iFNAME = 0;
    final int iLNAME = 1;
    final int iDOB = 2;
    final int iSSNUM = 3;
    final int iDIAG = 4;
    final int iTREAT = 5;
    final int iRX = 6;

    switch(PID){
      case 1:
      fileName = "BlockInput1.txt";
      break;
      case 2:
      fileName = "BlockInput2.txt";
      break;
      default:
      fileName = "BlockInput0.txt";
      break;
    }

    System.out.println("Using input file: " + fileName);

    try {
      try (BufferedReader fileReader = new BufferedReader(new FileReader(fileName))) {

        String inputText;
        String[] tokens = new String[10];
        UUID uuid;
        String uuidStr;

        while ((inputText = fileReader.readLine()) != null) {

          BlockRecord blockRecord = new BlockRecord();

          blockRecord.setPreviousHash("Previous hash goes here...");

          // Create a universal unique identifier for the block record. This
          // uuid, as well as a signed version, will be stored in the block data.
          uuid = UUID.randomUUID();
          uuidStr = new String(uuid.toString());
          blockRecord.setABlockID(uuidStr);

          // Send UUID (as byte array) and private key to signData method to
          // build signed UUID.
          byte[] digitalSignatureBlockID = signData(uuidStr.getBytes(), keyPair.getPrivate());
          blockRecord.setSignedBlockID(Base64.getEncoder().encodeToString(digitalSignatureBlockID));


          blockRecord.setACreatingProcess(Integer.toString(PID));
          blockRecord.setAVerificationProcessID("To be set later...");
          // The tokens are used to split the input text health data from the
          // files and input them into their respective block record fields.
          tokens = inputText.split(" +");
          blockRecord.setFSSNum(tokens[iSSNUM]);
          blockRecord.setFFname(tokens[iFNAME]);
          blockRecord.setFLname(tokens[iLNAME]);
          blockRecord.setFDOB(tokens[iDOB]);
          blockRecord.setGDiag(tokens[iDIAG]);
          blockRecord.setGTreat(tokens[iTREAT]);
          blockRecord.setGRx(tokens[iRX]);

          // Get current timestamp and set to dateCreated field in BlockRecord
          // for queue sorting purposes.
          Date date = new Date();
          String time = String.format("%1$s %2$tF.%2$tT", "", date);
          // Append process number of PID that created block to avoid
          // timestamp collisions
          String dateCreated = time + "." + PID + "\n";
          blockRecord.setDateCreated(dateCreated);

          // For testing purposes, print blockdata
          /*
          System.out.println("BlockID: " + blockRecord.getABlockID());
          System.out.println("Creating Process: " + blockRecord.getACreatingProcess());
          System.out.println("Verification Process: " + blockRecord.getAVerificationProcessID());
          System.out.println("SSN: " + blockRecord.getFSSNum());
          System.out.println("First name: " + blockRecord.getFFname());
          System.out.println("Last name: " + blockRecord.getFLname());
          System.out.println("DOB: " + blockRecord.getFDOB());
          System.out.println("Diagnosis: " + blockRecord.getGDiag());
          System.out.println("Treatment: " + blockRecord.getGTreat());
          System.out.println("Rx: " + blockRecord.getGRx());
          System.out.println();
          */

          // JAXB instance and Marshaller to convert java object to XML
          JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
          Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
          // StringWriter object to write BlockRecord as XML to StringWriter
          StringWriter stringWriter = new StringWriter();

          jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

          // Marshall BlockRecord to XML, write to stringWriter object
          jaxbMarshaller.marshal(blockRecord, stringWriter);
          // XML BlockRecord string
          String xmlBlock = stringWriter.toString();

          // Format the XML output
          jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

          blockRecord.setASHA256String("");
          blockRecord.setASignedSHA256("");

          System.out.println("Created unverified block for: " + blockRecord.getFFname() + " " + blockRecord.getFLname());
          System.out.println("Multicasting unverified block data: " + blockRecord.getFFname() + " " + blockRecord.getFLname());
          for(int i = 0; i < Blockchain.numProcesses; i++) {
            socket = new Socket(serverName, (Ports.UnverifiedBlockServerPortBase + i));
            oos = new ObjectOutputStream(socket.getOutputStream());
            // Send text as test to send unverified block
            // System.out.println("Sending Unverified Block test string to processes.");
            // Sleep to keep things running smoothly
            Thread.sleep(250);
            // Test passing first name of BlockRecord to every process
            // oos.writeObject(blockRecord.getFFname());
            oos.writeObject(xmlBlock);
            socket.close();
          }
        }
      } catch (IOException e) { e.printStackTrace(); }
    } catch(Exception x) { x.printStackTrace(); }
  }

// Method to check if Process 2 dummy server is running. If available, all other
// processes will start to execute.
  public static boolean processTwoAvailabilityCheck() {
    try (Socket socket1 = new Socket(serverName, (Ports.ServerAvailablePort))) {
      return true;
    } catch (Exception ex) { }
    return false;
  }

  public static void main(String args[]) {
    int q_len = 6;

    final BlockingQueue<BlockRecord> queue = new PriorityBlockingQueue<>();

    // The process id PID — initialized in class Blockchain, is set to the number
    // passed in as the first argument. If no argument is passed, default to 0.
    PID = (args.length < 1) ? 0 : Integer.parseInt(args[0]);
    System.out.println("Nathan Chmielewski's BlockFramework control-c to quit.\n");
    System.out.println("Using processID " + PID + "\n");

    // Call set Ports to establish ports number scheme for multiple threads
    // and processes for Public Key, Unverified Block, and Blockchain servers
    new Ports().setPorts();

    // Set default "dummy" first block in blockArray
    BlockRecord firstBlock = new BlockRecord();
    firstBlock.setBlockNum("1");
    firstBlock.setASHA256String("FirstBlock");
    firstBlock.setASignedSHA256("FirstBlock");
    firstBlock.setABlockID("FirstBlock");
    firstBlock.setAVerificationProcessID("FirstBlock");
    firstBlock.setACreatingProcess("FirstBlock");
    firstBlock.setPreviousHash("FirstBlock");
    firstBlock.setFFname("FirstBlock");
    firstBlock.setFLname("FirstBlock");
    firstBlock.setFSSNum("FirstBlock");
    firstBlock.setFDOB("FirstBlock");
    firstBlock.setGDiag("FirstBlock");
    firstBlock.setGTreat("FirstBlock");
    firstBlock.setGRx("FirstBlock");
    firstBlock.setDateCreated("FirstBlock");
    firstBlock.setSignedBlockID("FirstBlock");
    blockList.add(firstBlock);

    // Start server to accept and process incoming public key data
    new Thread(new PublicKeyServer(processBlocks)).start();
    // Start server to accept connection, and read in unverified block data
    new Thread(new UnverifiedBlockServer(queue)).start();
    // Start server to process incoming verified blockchain data
    new Thread(new BlockchainServer()).start();

    // This try block creates the process's KeyPair, passes the KeyPair's
    // PublicKey to multicast method to multicast it to all processes, and
    // calls multicast method to read in block data and store in unverified blocks.
    try {

      // Generate a private and public key pair for the process
      processKeyPair = generateKeyPair(PID);

      PublicKey processPublicKey = processKeyPair.getPublic();

      // Wait while the other processes/servers are started before beginning
      // to execute application.
      if (PID < 2) {
        boolean processTwoAvailable = false;
        System.out.println("Waiting for Process 2 to start.");

        while(!processTwoAvailable) {
          processTwoAvailable = processTwoAvailabilityCheck();
        }
      }
      // If Process 2, start dummy server to trigger all other processes to
      // begin execution
      if (PID == 2) {
        new Thread(new ServerAvailable()).start();
      }

      // Call multicast method to send this process's public key to all processes
      // in the multicast group. For this application, the public key is sent
      // to all three processes (0, 1, 2).
      MultiSendPublicKey(processPublicKey);
      try { Thread.sleep(2000); } catch(Exception e){ e.printStackTrace(); }

      // Call multicast method to read data input from file into unverified
      // block and multicast to all processes. For this application, the
      // unverified block is sent to all three processes (0, 1, 2).
      MultiSendUVBlock(processKeyPair);
      try { Thread.sleep(2000); } catch(Exception e){ e.printStackTrace(); }

    } catch(Exception x) {
      System.out.println("MultiSendPublicKey or UVBlockServer call error.");
      x.printStackTrace();
    }

    // Sleep statement to keep everything running smoothly
    try { Thread.sleep(1000); } catch(Exception e){ e.printStackTrace(); }

    // Start thread to take unverified blocks from queue and perform work to
    // add the block to the verified blockchain ledger.
    new Thread(new UnverifiedBlockConsumer(queue, processKeyPair, processBlocks)).start();
  }
}
