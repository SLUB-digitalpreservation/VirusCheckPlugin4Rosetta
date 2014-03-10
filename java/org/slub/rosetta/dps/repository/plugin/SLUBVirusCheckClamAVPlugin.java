package org.slub.rosetta.dps.repository.plugin;


import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Calendar;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.Iterator;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;


import com.exlibris.core.infra.common.exceptions.logging.ExLogger;
// import com.exlibris.dps.repository.plugin.virusCheck;
import com.exlibris.dps.repository.plugin.virusChcek.VirusCheckPlugin;

/**
 * SLUBVirusCheckClamAVPlugin
 *
 * ClamScan, should use clamdscan variant to avoid initialization overhead
 *
 * clamd-client opens a TCP-connection, see p18 in clamdoc.pdf
 * or source at https://github.com/vrtadmin/clamav-devel/blob/master/clamdscan/client.c
 * or source at https://github.com/vrtadmin/clamav-devel/blob/master/clamdscan/proto.c
 * code could also be copied from https://code.google.com/p/clamavj/source/browse/trunk/src/main/java/com/philvarner/clamavj/ClamScan.java?r=2
 * 
 * @author andreas.romeyke@slub-dresden.de (Andreas Romeyke)
 * @see 
 */
public class SLUBVirusCheckClamAVPlugin implements VirusCheckPlugin {
  //private static final ExLogger log = ExLogger.getExLogger(SLUBVirusCheckClamAVPlugin.class);
  private static final int DEFAULT_CHUNK_SIZE = 2048;
  private static final byte[] INSTREAM = "zINSTREAM\0".getBytes();
  private static final String RESPONSEOK = "stream: OK";
  private static final String FOUND_SUFFIX = "FOUND";
  private static final String STREAM_PREFIX = "stream: ";
  private enum Status { PASSED, FAILED };
  
  private int timeout;
  private String host;
  private int port;
  private String response;
  private Status status = Status.FAILED;
  private String signature = "";

  // constructor
  SLUBVirusCheckClamAVPlugin (String host, int port, int timeout) {
    this.host = host;
    this.port = port;
    this.timeout = timeout;
    //log.info("SLUBVirusCheckPlugin instantiated with host=" + host + " port=" + port + " timeout=" + timeout);
    System.out.println( "SLUBVirusCheckPlugin instantiated with host=" + host + " port=" + port + " timeout=" + timeout);
  }
  
  // getter, ex.: get Host, port, timeout
  protected String getHost() { return this.host; }
  protected int getPort() { return this.port; }
  protected int getTimeOut() { return this.timeout; }
  protected String getSignature() { return this.signature; }
  protected Status getStatus() { return status; }
  
  // setter  
  protected void setSignature(String signature) {
    this.signature = signature;
  }
  protected void setStatus(Status status) {
    this.status = status;
  }
  
  // scans a given file for viruses
  public void scan(String fileFullPath) {
  	try {
    // create a socket
    Socket socket = new Socket ();
    //socket.connect( new InetSocketAddress(getHost()));
    socket.connect( new InetSocketAddress(getHost(), getPort()));
    try {
      socket.setSoTimeout( getTimeOut() );
    } catch (SocketException e) {
    	System.out.println( "Could not set socket timeout to " + getTimeOut() + "ms " + e);
      //log.error( "Could not set socket timeout to " + getTimeOut() + "ms", e);
    }
    InputStream in = new FileInputStream( fileFullPath ); 
    // send stream
    DataOutputStream dos = null;
    response = "";
    try {
      dos = new DataOutputStream(socket.getOutputStream());
      dos.write(INSTREAM);
      int read;
      byte[] buffer = new byte[DEFAULT_CHUNK_SIZE];
      while ((read = in.read(buffer))> 0) {
        dos.writeInt(read);
        dos.write(buffer, 0, read);
      }
      dos.writeInt(0);
      dos.flush();
      read = socket.getInputStream().read(buffer);
      if (read > 0) response = new String(buffer, 0, read);
    } finally {
      if (dos != null) try { dos.close(); } catch (IOException e) { 
        // log.debug("exception closing DOS", e);
        System.out.println( "exception closing DOS "+ e );
      }
      try { socket.close(); } catch (IOException e) { 
        // log.debug("exception closing socket", e); 
        System.out.println( "exception closing socket "+ e);
      }
    }
    //log.debug( "Response: " + response);
    System.out.println("Response: " + response);
    // parse return code
    String result = response.trim();
    if (RESPONSEOK.equals( result ) ) {
      setStatus(Status.PASSED);
    } else if ( result.endsWith(FOUND_SUFFIX) ) {
      setStatus(Status.FAILED);
      setSignature(result.substring(STREAM_PREFIX.length(), result.lastIndexOf(FOUND_SUFFIX) - 1 ));
    } else {
      setStatus(Status.FAILED);
      //log.warn("clamd protocol not fully implemented");
      System.out.println("clamd protocol not fully implemented");
    }
    } catch (IOException e) {
    	//log.error("exception creation socket, clamd not available at host=" + host + "port=" + port, e);
    	System.out.println ("exception creation socket, clamd not available at host=" + host + "port=" + port + " " + e);
    	setStatus(Status.FAILED);
    	setSignature("ERROR: clamd not available");
    }
  }
  
  // outcome of virus check
  public String getOutput () {
    return getSignature();
  }
  
  public String getAgent () {
    return "clamd";
  }
  
  public boolean isVirusFree() {
    //return true; // dummy
    return (Status.PASSED  == getStatus());
  }
  
  // stand alone check
  public static void main(String [] args) {
  	SLUBVirusCheckClamAVPlugin plugin = new SLUBVirusCheckClamAVPlugin( "127.0.0.1", 3310, 60);
  	for (String file:args) {
  		plugin.scan( file );
  		System.out.println("RESULT: " + plugin.isVirusFree() + " SIGNATURE: " + plugin.getOutput());
  	}
	}
}


