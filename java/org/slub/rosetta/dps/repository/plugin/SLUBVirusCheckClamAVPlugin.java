package org.slub.rosetta.dps.repository.plugin;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Calendar;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.Iterator;

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
	// constructor
	SLUBVirusCheckClamAVPlugin () {
	}
	// scans a given file for viruses
	public void scan(String fileFullPath) {
	}
	// outcome of virus check
	public String getOutput () {
		return null; // dummy
	}
	public String getAgent () {
		return null; // dummy
	}
	public boolean isVirusFree() {
		return true; // dummy
	}
}


