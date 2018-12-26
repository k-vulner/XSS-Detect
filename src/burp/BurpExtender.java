package burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JToggleButton;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;

import com.alibaba.fastjson.JSONObject;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.Utilities.RandomStrLog;

public class BurpExtender extends AbstractTableModel
		implements IBurpExtender, ITab, IMessageEditorController, IHttpListener {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public static void main(String[] args) {
		// System.out.println(randomStr(1,"1"));
	}

	private static IBurpExtenderCallbacks callbacks;
	private static IExtensionHelpers helpers;
	private JPanel contentPane;
	private IMessageEditor requestViewer;
	private IMessageEditor responseViewer;
	private IHttpRequestResponse currentlyDisplayedItem;
	private static final List<LogEntry> log = new ArrayList<LogEntry>();
	SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd_HH:mm:ss");
	private static int intRequestId = 0;
	private static boolean isOpen = false;
	static HashMap<String, RandomStrLog> hashmapRequestIdWithStr = new HashMap<String, RandomStrLog>();
	static ArrayList<Integer> xssIdList = new ArrayList<Integer>();
	private static Color colorNoticing = new Color(255, 255, 0);
	private Table table1 = new Table(BurpExtender.this);
	// private TableModel tableModel = table1.getModel();

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		// TODO Auto-generated method stub
		new Utilities(callbacks);
		this.callbacks = callbacks;
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName("K-Vulner_XSS-Detect");

		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				contentPane = new JPanel();
				contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
				contentPane.setLayout(new BorderLayout(0, 0));

				JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
				JSplitPane panel1 = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
				tabbedPane.addTab("所有经测试请求包", null, panel1, null);

				JTabbedPane packetTabs = new JTabbedPane();
				requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
				responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
				packetTabs.addTab("Request", requestViewer.getComponent());
				packetTabs.addTab("Response", responseViewer.getComponent());

				JScrollPane scrollPane1 = new JScrollPane(table1);
				panel1.setLeftComponent(scrollPane1);
				panel1.setRightComponent(packetTabs);
				contentPane.add(tabbedPane, BorderLayout.CENTER);

				JToggleButton tglbtnNewToggleButton = new JToggleButton("未开启xss检测");

				tglbtnNewToggleButton.addActionListener(new ActionListener() {
					@Override
					public void actionPerformed(ActionEvent evt) {
						JToggleButton toggleBtn = (JToggleButton) evt.getSource();
						if (((JToggleButton) evt.getSource()).getModel().isSelected()) {
							toggleBtn.setText("正在XSS检测");
							isOpen = true;
						} else {
							toggleBtn.setText("未开启XSS检测");
							hashmapRequestIdWithStr.clear();
							xssIdList.clear();
							isOpen = false;
							intRequestId = 0;
							table1.clear();

						}
						// TODO Auto-generated method stub

					}

				});
				contentPane.add(tglbtnNewToggleButton, BorderLayout.NORTH);

				callbacks.customizeUiComponent(contentPane);
				callbacks.customizeUiComponent(tabbedPane);
				callbacks.customizeUiComponent(scrollPane1);

				callbacks.customizeUiComponent(packetTabs);
				callbacks.customizeUiComponent(table1);
				callbacks.customizeUiComponent(panel1);
				callbacks.addSuiteTab(BurpExtender.this);
				callbacks.registerHttpListener(BurpExtender.this);

			}
		});
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		// TODO Auto-generated method stub
		if (isOpen && (toolFlag == 4 || toolFlag == 64)) {
			try {

//				if (messageIsRequest) {
//					TraversalArgv(messageInfo, intRequestId);
//				} else {
//
//					// create a new log entry with the message details
//					synchronized (log) {
//
//						int row = log.size();
//						IHttpRequestResponsePersisted tmp = callbacks.saveBuffersToTempFiles(messageInfo);
//						// Utilities.out("respones!"+tmp.toString());
//						log.add(new LogEntry(intRequestId++, tmp, helpers.analyzeRequest(messageInfo).getUrl(),
//								df.format(new Date())));
//						fireTableRowsInserted(row, row);
//					}
//				}
				
				if (!messageIsRequest) {
					
					// create a new log entry with the message details
					synchronized (log) {

						int row = log.size();
						IHttpRequestResponsePersisted tmp = callbacks.saveBuffersToTempFiles(messageInfo);
						// Utilities.out("respones!"+tmp.toString());
						log.add(new LogEntry(intRequestId, tmp, helpers.analyzeRequest(messageInfo).getUrl(),
								df.format(new Date())));
						fireTableRowsInserted(row, row);
						TraversalArgv(messageInfo, intRequestId);
						intRequestId++;
					}
				}
			} catch (Exception e) {
				Utilities.err("188" + Utilities.printStackTraceToString(e.fillInStackTrace()));

			}
		}
	}

	public byte[] TraversalArgv(IHttpRequestResponse messageInfo, int requestId) {
		IRequestInfo requestInfo;
		byte[] request = messageInfo.getRequest();
		List<IParameter> requestParames;
		requestInfo = helpers.analyzeRequest(request);
		requestParames = requestInfo.getParameters();
		for (IParameter ipara : requestParames) {
			try {
				Utilities.out(ipara.getName() + ":" + ipara.getValue());
				IParameter tmpIpara;
				byte[] tmpRequest;
				IHttpRequestResponse tmpRespon;
				String strRequest;
				// Utilities.out(Integer.toHexString(ipara.getType()));
				if (ipara.getType() == IParameter.PARAM_JSON) {
					try {

						strRequest = helpers.bytesToString(request);
						String[] strArrayRequest = strRequest.split("\r\n\r\n");
						// Utilities.out(strArrayRequest[1].trim());
						JSONObject jsonObject = JSONObject.parseObject(strArrayRequest[1].trim());
						jsonObject.put(ipara.getName(), Utilities.randomStr(requestId, ipara.getName()));
						// Utilities.out(jsonObject.toString());
						tmpRequest = helpers.stringToBytes(strArrayRequest[0] + "\r\n\r\n" + jsonObject.toString());
						// Utilities.out(helpers.bytesToString(tmpRequest));
						tmpRespon = callbacks.makeHttpRequest(messageInfo.getHttpService(), tmpRequest);
						// Utilities.out(helpers.bytesToString(tmpRespon.getResponse()));
						search(tmpRespon, requestId, table1);
					} catch (Exception e) {
						Utilities.err("124" + Utilities.printStackTraceToString(e.fillInStackTrace()));
					}

				} else {
					try {
						tmpIpara = helpers.buildParameter(ipara.getName(),
								Utilities.randomStr(requestId, ipara.getName()), ipara.getType());
						tmpRequest = helpers.updateParameter(request, tmpIpara);
						// Utilities.out("begin"+helpers.bytesToString(tmpRequest)+"end");
						tmpRespon = callbacks.makeHttpRequest(messageInfo.getHttpService(), tmpRequest);
						// Utilities.out("respones!!!!"+helpers.bytesToString(tmpRespon.getResponse()));
						search(tmpRespon, requestId, table1);
					} catch (Exception e) {
						Utilities.err("238" + Utilities.printStackTraceToString(e.fillInStackTrace()));
					}

				}

			} catch (Exception e) {
				Utilities.err("243" + Utilities.printStackTraceToString(e.fillInStackTrace()));
			}

		}
		// Utilities.out(collab.generatePayload(true));
		// Utilities.out(collab.generatePayload(false));

		return request;

	}

	boolean search(IHttpRequestResponse messageInfo, int requestId, Table table1) {
		String tmpRespon = helpers.bytesToString(messageInfo.getResponse());
		for (Entry<String, RandomStrLog> tmp : Utilities.hashmapRequestIdWithStr.entrySet()) {
//			Utilities.out(tmp.getKey() + ":" + tmp.getValue().requestId + "_" + tmp.getValue().Argv);
			try {
				if (tmpRespon.contains(tmp.getKey())) {
//					Utilities.out("FIND IT!!" + tmp.getKey());
					xssIdList.add(requestId);
					setTableWhenFindVulner(table1, tmp.getValue().requestId, colorNoticing, requestId,
							tmp.getValue().Argv);
					return true;
				}
			} catch (Exception e) {
				Utilities.err("264" + Utilities.printStackTraceToString(e.fillInStackTrace()));
			}
		}

		return false;

	}

	private static void setTableWhenFindVulner(Table table, int rowIndex, Color color, int xssRequestId,
			String xssRequestArgv) {
		Utilities.out("rowIndex:"+String.valueOf(rowIndex)+" xssRequestId:"+String.valueOf(xssRequestId));
//		if(log.size()<=rowIndex){
//			sleep()
//		}
		
		try {
			synchronized (log) {
				String oriId = (String) table.getValueAt(rowIndex, 2);
				if (oriId == "null") {
					oriId = "";
				}
				log.get(rowIndex).xssid = oriId + " " + String.valueOf(xssRequestId);
				// table.setValueAt(oriId + " " +
				// String.valueOf(xssRequestId),rowIndex, 2);
				String oriArgv = (String) table.getValueAt(rowIndex, 3);
				if (oriArgv == "null") {
					oriArgv = "";
				}
				log.get(rowIndex).xssRequestArgv = oriArgv + " " + xssRequestArgv;
				// table.setValueAt(oriArgv + " " + xssRequestArgv, rowIndex,3);
				Utilities.out("rowIndex:" + String.valueOf(rowIndex));
				Utilities.out("oriId:" + oriId + String.valueOf(xssRequestId));
				Utilities.out("oriArgv:" + oriArgv + xssRequestArgv);
			}
		} catch (Exception e) {
			Utilities.err("263" + Utilities.printStackTraceToString(e.fillInStackTrace()));
		}
			
			try {
			DefaultTableCellRenderer tcr = new DefaultTableCellRenderer() {

				/**
				 * 
				 */
				private static final long serialVersionUID = 1L;

				public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
						boolean hasFocus, int row, int column) {
					if (xssIdList.contains(row)) {
						setBackground(color);
						setForeground(Color.BLACK);
						// Utilities.out(String.valueOf(row) + ":" +
						// String.valueOf(column) + ":!!!!yellow!!!!");
					} else {
						setBackground(Color.WHITE);
						setForeground(Color.BLACK);
						// Utilities.out(String.valueOf(row) + ":" +
						// String.valueOf(column) + ":white3333");
					}

					return super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
				}
			};
			int columnCount = table.getColumnCount();
			for (int i = 0; i < columnCount; i++) {
				table.getColumn(table.getColumnName(i)).setCellRenderer(tcr);
			}

		} catch (Exception e) {
			Utilities.err("3131" + Utilities.printStackTraceToString(e.fillInStackTrace()));
		}
	}

	@Override
	public String getTabCaption() {
		// TODO Auto-generated method stub
		return "K-Vulner_XSS-Detcet";
	}

	@Override
	public Component getUiComponent() {
		// TODO Auto-generated method stub
		return this.contentPane;
	}

	@Override
	public byte[] getRequest() {
		return currentlyDisplayedItem.getRequest();
	}

	@Override
	public byte[] getResponse() {
		return currentlyDisplayedItem.getResponse();
	}

	@Override
	public IHttpService getHttpService() {
		return currentlyDisplayedItem.getHttpService();
	}

	@Override
	public int getRowCount() {
		return log.size();
	}

	@Override
	public int getColumnCount() {
		return 6;
	}

	@Override
	public String getColumnName(int columnIndex) {
		switch (columnIndex) {
		case 0:
			return "请求包ID";
		case 1:
			return "发送时间";
		case 2:
			return "对应请求包ID";
		case 3:
			return "对应请求包入参";
		case 4:
			return "请求方法";
		case 5:
			return "URL地址";
		default:
			return "";
		}
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return String.class;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		// Utilities.out("row:"+String.valueOf(rowIndex)+"col:"+String.valueOf(columnIndex));
		try {
			LogEntry logEntry = log.get(rowIndex);

			switch (columnIndex) {
			case 0:
				return logEntry.id;
			case 1:
				return logEntry.requestTime;
			case 2:
				return logEntry.xssid;
			case 3:
				return logEntry.xssRequestArgv;
			case 4:
				return logEntry.requestResponse.getHighlight();
			case 5:
				return logEntry.url.toString();
			default:
				return "";
			}
		} catch (Exception e) {
			Utilities.err("361" + Utilities.printStackTraceToString(e.fillInStackTrace()));
		}
		return "";
	}

	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		super.setValueAt(aValue, rowIndex, columnIndex);
	}

	public boolean isCellEditable(int rowIndex, int columnIndex)

	{
		return true;

	}

	private class Table extends JTable {
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;

		public Table(TableModel tableModel) {
			super(tableModel);
		}

		public void clear() {
			log.clear();
			fireTableRowsDeleted(0, getRowCount());

		}

		@Override
		public void changeSelection(int row, int col, boolean toggle, boolean extend) {
			// show the log entry for the selected row
			LogEntry logEntry = log.get(row);
			requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
			responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
			currentlyDisplayedItem = logEntry.requestResponse;

			super.changeSelection(row, col, toggle, extend);
		}
	}

	private static class LogEntry {
		final int id;
		String xssid;
		String xssRequestArgv;
		final IHttpRequestResponsePersisted requestResponse;
		final URL url;
		final String requestTime;

		LogEntry(int id, IHttpRequestResponsePersisted requestResponse, URL url, String requestTime) {
			this.id = id;
			this.xssid = null;
			this.requestResponse = requestResponse;
			this.url = url;
			this.requestTime = requestTime;
			this.xssRequestArgv = null;
		}
	}

}
