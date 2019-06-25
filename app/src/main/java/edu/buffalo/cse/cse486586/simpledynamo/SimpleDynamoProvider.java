package edu.buffalo.cse.cse486586.simpledynamo;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Formatter;
import java.util.HashMap;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.database.MergeCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;
import static java.lang.String.valueOf;

public class SimpleDynamoProvider extends ContentProvider {
	private String myPort;
	HashMap<String, String> portToId = new HashMap<String, String>();
	String SingleQueryReturnFound = null;
	String queryAllString = null;
	String SinglePlus2ValueFound=null;
	boolean queryBlock=false;
	boolean insertBlock=false;
	boolean deleteBlock=false;
	//String SinglePlus2FromDifferentAVD=null;
	String[] avd_ports = {"11124","11112","11108","11116","11120"};
	public String getSuccessor(String port){
		for(int i=0; i < avd_ports.length; i++){
			if(port.equals(avd_ports[i])){
				if(i==avd_ports.length-1){
					return avd_ports[0];
				}else{
					return avd_ports[i+1];
				}
			}
		}
		return null;
	}
	public String getPredecssor(String port){
		for(int i=0; i < avd_ports.length; i++){
			if(port.equals(avd_ports[i])){
				if(i==0){
					return avd_ports[avd_ports.length-1];
				}else{
					return avd_ports[i-1];
				}
			}
		}
		return null;
	}
	public String dataBelongsto(String key){
		for(int i=0; i<avd_ports.length; i++){
			if(checkHash(key, avd_ports[i])){
				Log.e("Checking", key+" belongs to "+avd_ports[i]);
				return avd_ports[i];}
		}
		return null;
	}
	public boolean checkHash(String key, String port){
		String hashedKey = hashIt(key);
		String hashedPort = hashIt(portToId.get(port));
		String hashedPredecssor = hashIt(portToId.get(getPredecssor(port)));
		if(hashedKey.compareTo(hashedPort) <= 0 && hashedKey.compareTo(hashedPredecssor) > 0)
			return true;
		else if(hashedPort.compareTo(hashedPredecssor) <= 0){
			if(hashedKey.compareTo(hashedPredecssor) > 0 || hashedKey.compareTo(hashedPort) <= 0){
				return true;
			}
		}else{
			return false;
		}
		return false;
	}
	public synchronized void callForInsert(String key, String value, String primaryPort){
		String successor1 = getSuccessor(primaryPort);
		String successor2 = getSuccessor(successor1);
		new ClientTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, "insert-"+primaryPort+"-"+successor1+"-"+successor2+"-"+key+"-"+value);
	}
	public void deleteAllLocal(){
		Log.e("deleting", "everything from local avd");
		Context context = getContext();
		String[] fileList = context.fileList();
		if(fileList.length > 0){
			for (int i=0; i<fileList.length; i++){
				if(fileList[i].equals("flag"))
					continue;
				File file = new File(context.getFilesDir(), fileList[i]);
				if(file.exists()){
					file.delete();
				}
			}
		}
	}
	public void deleteSingleQuery(String filename){
		Context context = getContext();
		File file = new File(context.getFilesDir(), filename);
		if(file.exists())
			file.delete();
	}
	@Override
	public int delete(Uri uri, String selection, String[] selectionArgs) {
		Log.e("Asking for", "delete "+selection);
		if(selection.equals("*")){
			//delete all query
			deleteAllLocal();
			new ClientTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, "deleteAll");
		}
		else if(selection.equals("@")){
			deleteAllLocal();
		}
		else{
			Log.e("delete single key", selection);
			String keyOwner = dataBelongsto(selection);
			if(keyOwner.equals(myPort)){
				deleteSingleQuery(selection);
			}
			else{
				new ClientTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, "deleteSingle-"+keyOwner+"-"+selection);
			}
		}
		return 0;
	}
	@Override
	public String getType(Uri uri) {
		return null;
	}
	@Override
	public Uri insert(Uri uri, ContentValues values) {
		while(insertBlock){
			//
		}
		Log.e("Insert", values.toString());
		String key = values.get("key").toString();
		String value = values.get("value").toString();
		String dataBelongsTo = dataBelongsto(key);
		callForInsert(key, value, dataBelongsTo);
		return null;
	}
	public String hashIt(String s){
        try{
            String hashed = genHash(s);
            return hashed;
        }catch (NoSuchAlgorithmException e){
            Log.e("Algorithm", "Algo exception");
        }
        return null;
    }
    public Cursor queryAllLocal(){
		Log.e("Dumping all from avd", myPort);
		Context context = getContext();
		String[] fileList = context.fileList();
		MatrixCursor matrix = new MatrixCursor(new String[]{"key","value"});
		for(int i=0; i < fileList.length; i++){
			File file = new File(context.getFilesDir(), fileList[i]);
			StringBuilder txt = new StringBuilder();
			try {
				BufferedReader br = new BufferedReader(new FileReader(file));
				String line;
				while ((line = br.readLine()) != null) {
					txt.append(line);
				}
				String txts = txt.toString().substring(0, txt.length()-1);
				matrix.addRow(new Object[] {fileList[i], txts});
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
		return matrix;
	}
	public String queryAllLocalString(){
		String key_value = "";
		Log.e("Querying", "All local as a string");
		Context context = getContext();
		String[] fileList = context.fileList();
		for(int i=0; i < fileList.length; i++){
			if(fileList[i].equals("flag"))
				continue;
			File file = new File(context.getFilesDir(), fileList[i]);
			StringBuilder txt = new StringBuilder();
			try {
				BufferedReader br = new BufferedReader(new FileReader(file));
				String line;
				while ((line = br.readLine()) != null) {
					txt.append(line);
				}
				String txts = txt.toString().substring(0, txt.length()-1);
				if(key_value.equals(""))
					key_value = key_value + fileList[i] + "-" + txts;
				else
					key_value = key_value + "-" +fileList[i] + "-" + txts;
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
		return key_value;
	}
	public boolean checkFlagFile(){
		Context con = getContext();
		File file = new File(con.getFilesDir(), "flag");
		if(file.exists()){
			return true;
		}
		return false;
	}
	public void createFlagFile(){
		try{
		String value = "1";
		Context con = getContext();
		FileOutputStream outputStream;
		outputStream = new FileOutputStream(new File(con.getFilesDir(), "flag"));
		outputStream.write(value.getBytes());
		outputStream.close();}
		catch (Exception e){
			Log.e("Error", "creating flag file");
		}
	}
	@Override
	public boolean onCreate() {
		if(checkFlagFile()){
			insertBlock=true;
			queryBlock=true;
		}
		portToId.put("11108","5554");
		portToId.put("11112","5556");
		portToId.put("11116","5558");
		portToId.put("11120","5560");
		portToId.put("11124","5562");
		//myport
		TelephonyManager tel = (TelephonyManager) getContext().getSystemService(Context.TELEPHONY_SERVICE);
		String portToStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
		myPort = valueOf(Integer.parseInt(portToStr) * 2);
		Log.e("My port - ", myPort);
		//self id
		//creating socket
		try{
			ServerSocket serverSocket = new ServerSocket(10000);
			new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
		}catch (IOException e){
			e.printStackTrace();
			Log.e("Error : ","Socket cannot be created");
		}
		//to recover
		if(checkFlagFile()) {
			new ClientTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, "recovered");
		}
		else{
			createFlagFile();}
		//new ClientTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, "recovered");
		return false;
	}
	public Cursor parseAllQuerytoMatrix(String data){
		String[] n = data.split("-");
		MatrixCursor mat = new MatrixCursor(new String[]{"key","value"});
		for(int i=0; i < n.length; i++){
			mat.addRow(new Object[] {n[i], n[i+1]});
			i += 1;
		}
		return mat;
	}
	public synchronized Cursor doQuery(String selection){
		SingleQueryReturnFound = null;
		queryAllString = null;
		SinglePlus2ValueFound = null;
		Log.e("Query for", selection);
		if(selection.equals("*")){
			//query all avd
			String data = queryAllLocalString();
			new ClientTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, "queryAll--"+data);
			while(queryAllString == null){

				//Log.e("Waiting", "for all string data");
			}
			return parseAllQuerytoMatrix(queryAllString);
		}else if(selection.equals("@")){
			//local dump all //done modifying
			return queryAllLocal();
		}else{
			//single arg query
			String keyOwner = dataBelongsto(selection);
			if(keyOwner.equals(myPort)){
				String valueSingle = findSingleKey(selection); //key-value0
				String suc1 = getSuccessor(myPort);
				String suc2 = getSuccessor(suc1);
				new ClientTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, "querySelfPlus2-"+suc1+"-"+suc2+"-"+selection+"-"+valueSingle);
				while(SinglePlus2ValueFound == null){
					//
				}
				MatrixCursor mat1 = new MatrixCursor(new String[]{"key", "value"});
				mat1.addRow(new Object[] {selection, SinglePlus2ValueFound});
				return mat1;
			}
			else {
				String sc1 = getSuccessor(keyOwner);
				String sc2 = getSuccessor(sc1);
				new ClientTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, "querySingle-"+keyOwner+"-"+sc1+"-"+sc2+"-"+selection);
				while (SingleQueryReturnFound == null) {
					//Log.e("Waiting for data", "Single Query");
				}
				MatrixCursor mat = new MatrixCursor(new String[]{"key", "value"});
				mat.addRow(new Object[]{selection, SingleQueryReturnFound});
				return mat;
			}
		}
	}
	@Override
	public Cursor query(Uri uri, String[] projection, String selection,
			String[] selectionArgs, String sortOrder) {
		while (queryBlock){
			//
		}
		Log.e("Query", "searching for "+selection);
		Cursor m = doQuery(selection);
		return m;
	}
	@Override
	public int update(Uri uri, ContentValues values, String selection,
			String[] selectionArgs) {
		return 0;
	}
    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }
	public boolean insertSinglePair(String key, String value){
		Log.e("Inserting", key+"in avd "+myPort);
		Context con = getContext();
		FileOutputStream outputStream;
		try{
			File file = new File(con.getFilesDir(), key);
			if(file.exists()){
				String countValue = findSingleKey(key);
				String counter = countValue.substring(countValue.length()-1);
				int cnt = Integer.parseInt(counter);
				cnt += 1;
				value = value + String.valueOf(cnt);
				outputStream = new FileOutputStream(new File(con.getFilesDir(), key));
				outputStream.write(value.getBytes());
				outputStream.close();
				Log.e("Inserted updated value", value);
			}
			else {
				value = value + "0";
				outputStream = new FileOutputStream(new File(con.getFilesDir(), key));
				outputStream.write(value.getBytes());
				outputStream.close();
				Log.e("Inserted first value", value);
			}
		}catch (Exception e){
			e.printStackTrace();
		}
		return true;
	}
	public String findSingleKey(String key){
		Context context = getContext();
		File file = new File(context.getFilesDir(), key);
		StringBuilder txt = new StringBuilder();
		try {
			BufferedReader br = new BufferedReader(new FileReader(file));
			String line;
			while((line = br.readLine()) != null){
				txt.append(line);
			}
			Log.e("Single Key", "<<Found>>");
		}catch (IOException e){
			e.printStackTrace();
			//File not found
			Log.e("Not found", "File not found for key "+key);
		}

		return txt.toString();
	}
	public String querylocalrecovered(String port, String orig){
		String key_value = "";
		Log.e("Querying", "recovery data from "+port+" for "+orig);
		Context context = getContext();
		String[] fileList = context.fileList();
		for(int i=0; i < fileList.length; i++) {
			if(fileList[i].equals("flag"))
				continue;
			if (dataBelongsto(fileList[i]).equals(port)) {
				//Log.e("recovery", fileList[i]);
				File file = new File(context.getFilesDir(), fileList[i]);
				StringBuilder txt = new StringBuilder();
				try {
					BufferedReader br = new BufferedReader(new FileReader(file));
					String line;
					while ((line = br.readLine()) != null) {
						txt.append(line);
					}
					if (key_value.equals(""))
						key_value = key_value + fileList[i] + "-" + txt;
					else
						key_value = key_value + "-" + fileList[i] + "-" + txt;
					Log.e("recovery", fileList[i]+", "+txt);
				} catch (IOException e) {
					e.printStackTrace();
				}

			}
		}
		return key_value;
	}
    private class ServerTask extends AsyncTask<ServerSocket, String, Void>{
		protected Void doInBackground(ServerSocket... sockets){
			ServerSocket serverSocket = sockets[0];
			Log.e("Server", "Socket created");
			while(true){
				try{
					Socket socket = serverSocket.accept();
					BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
					PrintWriter pf = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));
					String message = br.readLine();
					if(message != null && message.startsWith("insert")){ //0-insert, 1-key, 2-value
						while(insertBlock){
							//
						}
						String[] insertServer = message.split("-");
						if(insertSinglePair(insertServer[1], insertServer[2])){
							pf.println("ACK");
							pf.flush();
						}
					}
					else if(message != null && message.startsWith("querySingle")){
						while(queryBlock){

						}
						//SinglePlus2FromDifferentAVD = null;
						String[] querySingleServer = message.split("-"); //1-key
						String value = findSingleKey(querySingleServer[1]);
						Log.e("Query", "for key "+querySingleServer[1]);

						pf.println(value);
						pf.flush();
					}
					else if(message != null && message.equals("queryAll")){
						String data = queryAllLocalString();
						pf.println(data);
						pf.flush();
					}
					else if(message != null && message.startsWith("deleteSingle")){ //1-key
						String key[] = message.split("-");
						deleteSingleQuery(key[1]);
						socket.close();
					}
					else if(message != null && message.equals("deleteAll")){
						socket.close();
						deleteAllLocal();
					}
					else if(message != null && message.startsWith("querySinglePlus2")){
						String[] key = message.split("-");
						 String val = findSingleKey(key[1]);
						 pf.println(val);
						 pf.flush();
					}
					else if(message != null && message.startsWith("pre")){
						//self keyshashed string return
						String[] r = message.split("-");
						String key_value = querylocalrecovered(myPort, r[1]);
						Log.e("sending recovered data", key_value);
						pf.println(key_value);
						pf.flush();
					}
					else if(message != null && message.startsWith("suc")){
						//requested avdhashed return
						String[] r = message.split("-");
						String key_value = querylocalrecovered(r[1], r[1]);
						Log.e("sending recovered data", key_value);
						pf.println(key_value);
						pf.flush();
					}
				}catch (IOException eserver){
					Log.e("Server", "<<< Server exception >>>");
				}
			}
		}
	}
	private class ClientTask extends AsyncTask<String, Void, Void>{
		protected Void doInBackground(String... msgs){
			//try{
				String msg = msgs[0];
				if(msg.startsWith("insert")){
					//TODO - handle exception for insert if avd failed.
					String[] insert = msg.split("-"); //insert0 - insert, 1 - mainport, 2- suc1, 3- suc2, 4-key, 5-value
					for(int i=1; i < 4; i++) {
						try {
							Log.e("Sending", "Insert message to" + insert[i]);
							Socket socket0 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(insert[i]));
							PrintWriter pf0 = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket0.getOutputStream())));
							BufferedReader br0 = new BufferedReader(new InputStreamReader(socket0.getInputStream()));
							pf0.println("insert-" + insert[4] + "-" + insert[5]);
							pf0.flush();
							socket0.setSoTimeout(1000);
							String replyInsert = br0.readLine();
							if(replyInsert != null && replyInsert.equals("ACK")){
								socket0.close();
							}
						}catch (IOException einsert){
							einsert.printStackTrace();
							Log.e("ClientTask", "<<< exception while sending insert data >>>");

						}
					}
					Log.e("..", "<< Insert in all three completed >>");
				}
				else if(msg.startsWith("querySingle")) {
					String[] querySingle = msg.split("-"); // 0-query, 1-owner, 2-sc1, 3-sc2, 4-key
					String data = "";
					for (int i = 1; i < 4; i++){
						try {
							//Log.e("Querying", "Single key argument to "+querySingle[1]);
							Socket socket1 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(querySingle[i]));
							PrintWriter pf1 = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket1.getOutputStream())));
							BufferedReader br1 = new BufferedReader(new InputStreamReader(socket1.getInputStream()));
							pf1.println("querySingle-" + querySingle[4]);
							pf1.flush();
							socket1.setSoTimeout(1000);
							String valueReply = br1.readLine();
							if (valueReply != null) {
								socket1.close();
								if(valueReply.length() > 0) {
									if (data.length() == 0) {
										data = data + valueReply;
									} else {
										data = data + "-" + valueReply;
									}
								}
							}
						} catch (IOException equerysingle) {
							Log.e("Clientask", "<<< exception in single query >>>");
						}
					}
					Log.e("recieved values queries", data);
					if(data.length() > 0)
						SingleQueryReturnFound = findMaxValue(data);
				}
				else if(msg.startsWith("queryAll")){
					String[] queryAll = msg.split("--"); //1-data
					String allData = queryAll[1];
					for(int i=0; i<avd_ports.length; i++){
						try{
							if(avd_ports[i].equals(myPort))
								continue;
							Log.e("Send queryall req to ", avd_ports[i]);
							Socket socket2 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(avd_ports[i]));
							PrintWriter pf2 = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket2.getOutputStream())));
							BufferedReader br2 = new BufferedReader(new InputStreamReader(socket2.getInputStream()));
							pf2.println("queryAll");
							pf2.flush();
							socket2.setSoTimeout(1000);
							String reply = br2.readLine();
							if(reply != null){
								socket2.close();
								allData = allData + "-" + reply;
							}
						}catch (IOException equeryAll){
							Log.e("Clientask", "query all exception");
						}
					}
					queryAllString = allData;
				}
				else if(msg.startsWith("deleteSingle")){
					String[] deleteSingle = msg.split("-"); //1-keywoner, 2-key
					String mainPort = deleteSingle[1];
					String suc1 = getSuccessor(mainPort);
					String suc2 = getSuccessor(suc1);
					String[] avds = {mainPort, suc1, suc2};
					for(int i=0; i<avds.length; i++) {
						try {
							Socket socket3 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(avds[i]));
							PrintWriter pf3 = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket3.getOutputStream())));
							pf3.println("deleteSingle-" + deleteSingle[2]);
							pf3.flush();
						} catch (IOException edeleteSingle) {
							Log.e("Clientask", "exception delete single");
						}
					}
				}
				else if(msg.equals("deleteAll")){
					for(int i=0; i<avd_ports.length; i++){
						try{
							if(avd_ports[i].equals(myPort))
								continue;
							Socket socket4 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(avd_ports[i]));
							PrintWriter pf4 = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket4.getOutputStream())));
							pf4.println("deleteAll");
							pf4.flush();
						}catch (IOException edeleteAll){
							Log.e("Clientask", "delete all exception");
						}
					}
				}
				else if (msg.startsWith("querySelfPlus2")){
					String data = "";
					String[] self = msg.split("-");//1-suc1, 2-suc2, 3-selection, 4-valueofmain
					if(self.length == 5){
						data = self[4];
					}

					//with counter
					for(int i=1; i<3; i++){
						try{
							Socket socket5 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(self[i]));
							PrintWriter pf5 = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket5.getOutputStream())));
							BufferedReader br5 = new BufferedReader(new InputStreamReader(socket5.getInputStream()));
							pf5.println("querySinglePlus2-"+self[3]);
							pf5.flush();
							socket5.setSoTimeout(1000);
							String rr = br5.readLine();
							if(rr != null){
								socket5.close();
								if(data.equals("")){
									data = data + rr;
								}
								else{
									data = data + "-" + rr;
								}
							}
						}catch (IOException edeleteAll){
							Log.e("Clientask", "delete all exception");
						}
					}
					//String maxValue = findMaxValue(data);
					if(data.length() > 0)
						SinglePlus2ValueFound = findMaxValue(data);
				}
				else if(msg.startsWith("recovered")){
					Log.e("Starting", "recovery process");
					deleteAllLocal();
					Log.e("deleting", "delete local completed");
					String pre1 = getPredecssor(myPort);
					String pre2 = getPredecssor(pre1);
					String suc1 = getSuccessor(myPort);
					String[] avvd = {pre1, pre2, suc1};
					String[] mess = {"pre", "pre", "suc"};
					for(int i=0; i<3; i++){
						try{
							Socket socket6 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(avvd[i]));
							PrintWriter pf6 = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket6.getOutputStream())));
							BufferedReader br6 = new BufferedReader(new InputStreamReader(socket6.getInputStream()));
							pf6.println(mess[i]+"-"+myPort);
							pf6.flush();
							//socket6.setSoTimeout(2000);
							String rep = br6.readLine(); //key-value
							if(rep != null && rep.length() > 0){
								socket6.close();
								parseAndInsert(rep);
								Log.e("recved recovered data- "+avvd[i], rep);
							}
						}catch (IOException erecover){
							Log.e("Exception", "recover exception by "+avvd[i]);
							erecover.printStackTrace();
						}
					}
					insertBlock=false;
					queryBlock=false;
					Log.e("DOne", "recovery completed");
				}
//			}catch (IOException e){
//				e.printStackTrace();
//				Log.e("Error", "<<<ClientTask Exception>>>");
//			}


			return null;
		}
	}
	public void parseAndInsert(String key_value){
		String[] z = key_value.split("-");
		Log.e("lenght of z", String.valueOf(z.length));
		for(int i=0; i < z.length; i++) {
			try{
			String key = z[i];
			String value = z[i+1];
			Context con = getContext();
			FileOutputStream outputStream;
			outputStream = new FileOutputStream(new File(con.getFilesDir(), key));
			outputStream.write(value.getBytes());
			outputStream.close();
			i += 1;
			}
			catch (IOException e){
				Log.e("exeption", "while inserting recovered data");
			}
		}
	}
	public String findMaxValue(String values){
		String[] val = values.split("-");
		int max = 0;
		String maxVal = val[0].substring(0, val[0].length()-1);
		for(int i=0; i<val.length; i++){
			int cnt = Integer.parseInt(val[i].substring(val[i].length()-1));
			if(cnt > max){
				max = cnt;
				maxVal = val[i].substring(0, val[i].length()-1);
			}
		}
		return maxVal;
	}
}
