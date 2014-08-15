/* 
2014 by Andreas Romeyke (SLUB Dresden)

The code is partially based on https://code.google.com/p/clamavj/source/browse/trunk/src/main/java/com/philvarner/clamavj/ClamScan.java?r=2
 https://github.com/vrtadmin/clamav-devel/blob/master/clamdscan/client.c and 
 https://github.com/vrtadmin/clamav-devel/blob/master/clamdscan/proto.c

 and therefore licensed under apache 2.0.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package org.slub.rosetta.dps.repository.plugin;


import com.exlibris.dps.repository.plugin.virusChcek.VirusCheckPlugin;

import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.util.HashMap;
import java.util.Map;


/**
 * SLUBVirusCheckClamAVPlugin
 * <p/>
 * ClamScan, should use clamdscan variant to avoid initialization overhead
 * <p/>
 * clamd-client opens a TCP-connection, see p18 in clamdoc.pdf
 * or source at https://github.com/vrtadmin/clamav-devel/blob/master/clamdscan/client.c
 * or source at https://github.com/vrtadmin/clamav-devel/blob/master/clamdscan/proto.c
 * code could also be copied from https://code.google.com/p/clamavj/source/browse/trunk/src/main/java/com/philvarner/clamavj/ClamScan.java?r=2
 *
 * @author andreas.romeyke@slub-dresden.de (Andreas Romeyke)
 * @see com.exlibris.dps.repository.plugin.virusChcek.VirusCheckPlugin 
 */
public class SLUBVirusCheckClamAVPlugin implements VirusCheckPlugin {
    //private static final ExLogger log = ExLogger.getExLogger(SLUBVirusCheckClamAVPlugin.class);
    private static final int DEFAULT_CHUNK_SIZE = 2048;
    private static final byte[] INSTREAM = "zINSTREAM\0".getBytes();
    private static final byte[] VERSION = "zVERSION\0".getBytes();
    private static final String RESPONSEOK = "stream: OK";
    private static final String FOUND_SUFFIX = "FOUND";
    private static final String STREAM_PREFIX = "stream: ";
    private int timeout;
    private String host;
    private int port;
    private String response;
    private Status status = Status.FAILED;
    private String signature = "";
    private enum Status {PASSED, FAILED};
    /** constructor */
    public SLUBVirusCheckClamAVPlugin() {
        //log.info("SLUBVirusCheckPlugin instantiated with host=" + host + " port=" + port + " timeout=" + timeout);
        System.out.println("SLUBVirusCheckPlugin instantiated");
    }
    /** init params to configure the plugin via xml forms
     * @param initp parameter map
     */
    public void initParams(Map<String, String> initp) {
        this.host = initp.get("host");
        this.port = Integer.parseInt(initp.get("port"));
        this.timeout = Integer.parseInt(initp.get("timeout"));
        //log.info("SLUBVirusCheckPlugin instantiated with host=" + host + " port=" + port + " timeout=" + timeout);
        System.out.println("SLUBVirusCheckPlugin instantiated with host=" + host + " port=" + port + " timeout=" + timeout);
    }
    /** stand alone check, main file to call local installed clamd
     * @param args list of files which should be scanned
     */
    public static void main(String[] args) {
        SLUBVirusCheckClamAVPlugin plugin = new SLUBVirusCheckClamAVPlugin();
        Map<String, String> initp = new HashMap<String, String>();
        initp.put( "host", "127.0.0.1");
        initp.put( "port", "3310");
        initp.put( "timeout", "60");
        plugin.initParams( initp );
        System.out.println("Agent: " + plugin.getAgent());
        for (String file : args) {
            plugin.scan(file);
            System.out.println("RESULT: " + plugin.isVirusFree() + " SIGNATURE: " + plugin.getOutput());
        }
    }

    /** get host
     *
     * @return host
     */
    protected String getHost() {
        return this.host;
    }

    /** get port
     *
     * @return port number
     */
    protected int getPort() {
        return this.port;
    }

    /** get timeout
     *
     * @return timeout in ms
     */
    protected int getTimeOut() {
        return this.timeout;
    }

    /** get signature of last scanned file
     *
     * @return signature name
     */
    protected String getSignature() {
        return this.signature;
    }

    /** set signature of last scanned file
     *
     * @param signature signature of last scanned file
     */
    protected void setSignature(String signature) {
        this.signature = signature;
    }

    /** get status of last scan
     *
     * @return status of last scan
     */
    protected Status getStatus() {
        return status;
    }

    /** set status of last scan
     *
     * @param status status of last scan
     */
    protected void setStatus(Status status) {
        this.status = status;
    }

    /** helper to cat 'in' stream to 'dos' stream for socket communication
     *
     * @param in raw input stream 'in'
     * @param dos special outputstream 'dos' for socket communication special for clamd
     * @param buffer buffer to buffer cat
     * @throws IOException if something goes wrong
     */
    private void writeStreamToStream(InputStream in, DataOutputStream dos, byte[] buffer) throws IOException {
        int read;
        while ((read = in.read(buffer)) > 0) {
            dos.writeInt(read);
            dos.write(buffer, 0, read);
        }
        dos.writeInt(0);
    }

    /** opens a socket
     *
     * @return socket
     * @throws IOException if soemthing goes wrong
     */
    private Socket openSocket() throws IOException {
        // create a socket
        Socket socket = new Socket();
        //socket.connect( new InetSocketAddress(getHost()));
        socket.connect(new InetSocketAddress(getHost(), getPort()));
        try {
            socket.setSoTimeout(getTimeOut());
        } catch (SocketException e) {
            System.out.println("Could not set socket timeout to " + getTimeOut() + "ms " + e);
            //log.error( "Could not set socket timeout to " + getTimeOut() + "ms", e);
        }
        return socket;
    }

    /** close socket
     *
     * @param socket socket which should be closed
     * @param dos associated outputstream to socket
     */
    private void closeSocket(Socket socket, DataOutputStream dos) {
        if (dos != null) try {
            dos.close();
        } catch (IOException e) {
            // log.debug("exception closing DOS", e);
            System.out.println("exception closing DOS " + e);
        }
        try {
            socket.close();
        } catch (IOException e) {
            // log.debug("exception closing socket", e);
            System.out.println("exception closing socket " + e);
        }
    }


    /** calls a simple clamd command via socket
     *
     * @param socket opened socket
     * @param command clamd command
     * @throws IOException if something goes wrong
     */
    private void callSocketCommand(Socket socket, byte[] command) throws IOException {
        DataOutputStream dos = null;
        try {
            dos = new DataOutputStream(socket.getOutputStream());
            dos.write(command);
            int read;
            byte[] buffer = new byte[DEFAULT_CHUNK_SIZE];
            dos.flush();
            read = socket.getInputStream().read(buffer);
            if (read > 0) response = new String(buffer, 0, read);
        } finally {
            closeSocket(socket, dos);
        }
    }

    /** calls an extended clamd command via socket, which expects an additional data inputstream which should be sent
     *
     * @param socket opened socket
     * @param command clamd command
     * @param in input stream which should be sent to clamd
     * @throws IOException if something goes wrong
     */
    private void callSocketCommandStream(Socket socket, byte[] command, InputStream in) throws IOException {
        DataOutputStream dos = null;
        try {
            dos = new DataOutputStream(socket.getOutputStream());
            dos.write(command);
            int read;
            byte[] buffer = new byte[DEFAULT_CHUNK_SIZE];
            writeStreamToStream(in, dos, buffer);
            dos.flush();
            read = socket.getInputStream().read(buffer);
            if (read > 0) response = new String(buffer, 0, read);
        } finally {
            closeSocket(socket, dos);
        }
    }

    /** scans a given file for viruses
     *
     * @param fileFullPath scans given file via clamd
     */
    public void scan(String fileFullPath) {
        try {
            Socket socket = openSocket();

            InputStream in = new FileInputStream(fileFullPath);
            // send stream
            response = "";
            byte[] command = INSTREAM;
            callSocketCommandStream(socket, command, in);
            in.close();
            //log.debug( "Response: " + response);
            System.out.println("Response: " + response.trim());
            // parse return code
            String result = response.trim();
            if (RESPONSEOK.equals(result)) {
                setStatus(Status.PASSED);
            } else if (result.endsWith(FOUND_SUFFIX)) {
                setStatus(Status.FAILED);
                setSignature(result.substring(STREAM_PREFIX.length(), result.lastIndexOf(FOUND_SUFFIX) - 1));
            } else {
                setStatus(Status.FAILED);
                //log.warn("clamd protocol not fully implemented");
                System.out.println("clamd protocol not fully implemented");
            }
        } catch (IOException e) {
            //log.error("exception creation socket, clamd not available at host=" + host + "port=" + port, e);
            System.out.println("exception creation socket, clamd not available at host=" + host + "port=" + port + " " + e);
            setStatus(Status.FAILED);
            setSignature("ERROR: clamd not available");
        }
    }

    /** outcome of virus check
     *
     * @return signature of last scan
     */
    public String getOutput() {
        return getSignature();
    }

    /** get clamd agent version and signature version calling clamd-command VERSION
     *
     * @return string with clamd version and signature version
     */
    public String getAgent() {
        try {
            // create a socket
            Socket socket = openSocket();
            byte[] command = VERSION;
            response = "";
            callSocketCommand(socket, command);
            return response.trim();
        } catch (IOException e) {
            //log.error("exception creation socket, clamd not available at host=" + host + "port=" + port, e);
            System.out.println("exception creation socket, clamd not available at host=" + host + "port=" + port + " " + e);
            setStatus(Status.FAILED);
            setSignature("ERROR: clamd not available");
            return "ERROR: clamd not available";
        }
    }

    /** result of last scan
     *
     * @return true if last scan passed (means: virus free)
     */
    public boolean isVirusFree() {
        //return true; // dummy
        return (Status.PASSED == getStatus());
    }
}


