import sys
from PyQt6.QtWidgets import QApplication, QWidget, QTableWidget, QTableWidgetItem, QPushButton, QVBoxLayout, QFileDialog, QLabel, QFrame, QMainWindow, QHeaderView
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPalette, QColor
import pandas as pd
import os
from PyQt6 import QtCore, QtGui, QtWidgets
import numpy as np
import pickle
import seal
from pathlib import Path
sys.path.insert(0, 'cryptotree')
from cryptoTree import HomomorphicTreeFeaturizer
from tqdm import tqdm
import csv
import requests
from config import scale

path = Path("seal_for_client")
parms = seal.EncryptionParameters(seal.scheme_type.ckks)
parms.load(str(path/"parms"))

context = seal.SEALContext(parms, True, seal.sec_level_type.tc128)

public_key = seal.PublicKey()
public_key.load(context, str(path/"public_key"))

secret_key = seal.SecretKey()
secret_key.load(context, str(path/"secret_key"))

encoder = seal.CKKSEncoder(context)
encryptor = seal.Encryptor(context, public_key)
decryptor = seal.Decryptor(context, secret_key)


comparator = np.load("setup\comparator.npy")


pipe = pickle.load(open("setup\pipe.pkl", "rb"))
homomorphic_featurizer = HomomorphicTreeFeaturizer(comparator, encoder, encryptor, scale)


# Initialize SocketIO client
import socketio
sio = socketio.Client()

class Ui_csvdtgv(object):
    def setupUi(self, csvdtgv):
        csvdtgv.setObjectName("csvdtgv")
        csvdtgv.resize(1273, 699)
        csvdtgv.setStyleSheet("#csvdtgv{\n"
"    background-color: rgb(255,255,255);\n"
"}\n"
"\n"
"#Header {\n"
"    background: qlineargradient( x1:0 y1:0, x2:1 y2:0, stop:0 rgb(156,252,248), stop:1 rgb(110,123,251));\n"
"}\n"
"\n"
"#Header #Logo{\n"
"    image: url(:/Pic/logo.jpg);\n"
"    border: none;\n"
"}\n"
"\n"
"#Header #NameSW{\n"
"    font-family: \"Robotol\", sans-serif;\n"
"    font-size: 25px;\n"
"    font-weight: bold;\n"
"    text-algin: left;\n"
"}\n"
"\n"
"#Header #inputfilename{\n"
"    font-size: 14px;\n"
"    font: 8pt \"8514oem\";\n"
"    text-algin: center;\n"
"}\n"
"\n"
"#result_frame {\n"
"    border-radius: 10px;\n"
"    border: 1px solid black;\n"
"    background-color: #fff;\n"
"}\n"
"\n"
"QTableWidget {\n"
"    border-radius: 3px;\n"
"    border: 1px solid #f0f0f0;\n"
"}\n"
"\n"
"QHeaderView::section {\n"
"    border: none;\n"
"    border-bottom: 1px solid black;\n"
"    text-align: left;\n"
"    padding: 3px 5px;\n"
"}\n"
"\n"
"QTableWidget::Item {\n"
"    border-bottom: 1px solid rgb(212, 212, 212);\n"
"    color: #000;\n"
"    padding-left: 3px;\n"
"}\n"
"\n"
"#btn_frame {\n"
"    border: 1px solid black;\n"
"    border-radius: 10px;\n"
"    background-color: rgb(255,255,255);\n"
"}\n"
"\n"
"#btn_frame QPushButton{\n"
"    background: qlineargradient( x1:0 y1:0, x2:1 y2:0, stop:0 rgb(255, 190, 61), stop:1 rgb(240, 101, 67));\n"
"    border-radius: 10px;\n"
"    font-size: 14px;\n"
"    font: 8pt \"8514oem\";\n"
"}\n"
"\n"
"\n"
"#btn_frame QPushButton:hover{\n"
"    background: qlineargradient( x1:0 y1:0, x2:1 y2:0, stop:0 rgb(240, 101, 67), stop:1 rgb(255, 190, 61));\n"
"    color: rgb(255, 255, 255);\n"
"}\n"
"\n"
"#statelabel{\n"
"    padding-left: 10px;\n"
"    border-radius: 10px;\n"
"    background-color: rgb(224, 224, 224);\n"
"    font-size: 14px;\n"
"    font: 8pt \"8514oem\";\n"
"    color: rgb(255, 0, 0);\n"
"}\n"
"QProgressBar {\n"
"    border: 2px solid grey;\n"
"    border-radius: 5px;\n"
"    background-color: #FFFFFF;\n"
"    text-align: center;\n"
"    font-size: 14px;\n"
"    font: 8pt \"8514oem\";\n"
"}\n"
"\n"
"QProgressBar::chunk {\n"
"    background-color: rgb(156,252,248);\n"
"}\n"
"\n"
"\n"
"\n"
"")
        self.centralwidget = QtWidgets.QWidget(parent=csvdtgv)
        self.centralwidget.setObjectName("centralwidget")
        self.Header = QtWidgets.QFrame(parent=self.centralwidget)
        self.Header.setGeometry(QtCore.QRect(0, 0, 1281, 71))
        self.Header.setStyleSheet("")
        self.Header.setObjectName("Header")
        self.NameSW = QtWidgets.QLabel(parent=self.Header)
        self.NameSW.setGeometry(QtCore.QRect(80, 20, 341, 31))
        font = QtGui.QFont()
        font.setFamily("Robotol")
        font.setPointSize(-1)
        font.setBold(True)
        font.setWeight(75)
        self.NameSW.setFont(font)
        self.NameSW.setStyleSheet("")
        self.NameSW.setAlignment(QtCore.Qt.AlignmentFlag.AlignBottom|QtCore.Qt.AlignmentFlag.AlignLeading|QtCore.Qt.AlignmentFlag.AlignLeft)
        self.NameSW.setObjectName("NameSW")
        self.inputfilename = QtWidgets.QLabel(parent=self.Header)
        self.inputfilename.setGeometry(QtCore.QRect(580, 30, 661, 20))
        font = QtGui.QFont()
        font.setFamily("8514oem")
        font.setPointSize(8)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        self.inputfilename.setFont(font)
        self.inputfilename.setStyleSheet("")
        self.inputfilename.setAlignment(QtCore.Qt.AlignmentFlag.AlignBottom|QtCore.Qt.AlignmentFlag.AlignLeading|QtCore.Qt.AlignmentFlag.AlignLeft)
        self.inputfilename.setObjectName("inputfilename")
        self.label = QtWidgets.QLabel(parent=self.Header)
        self.label.setGeometry(QtCore.QRect(16, 10, 51, 51))
        self.label.setText("")
        self.label.setPixmap(QtGui.QPixmap("logo.jpg"))
        self.label.setScaledContents(True)
        self.label.setObjectName("label")
        self.widget = QtWidgets.QWidget(parent=self.centralwidget)
        self.widget.setGeometry(QtCore.QRect(0, 70, 1271, 631))
        self.widget.setStyleSheet("")
        self.widget.setObjectName("widget")
        self.result_frame = QtWidgets.QFrame(parent=self.widget)
        self.result_frame.setGeometry(QtCore.QRect(30, 120, 1211, 481))
        self.result_frame.setStyleSheet("")
        self.result_frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.result_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.result_frame.setObjectName("result_frame")
        self.gridLayout = QtWidgets.QGridLayout(self.result_frame)
        self.gridLayout.setObjectName("gridLayout")
        self.tableWidget = QtWidgets.QTableWidget(parent=self.result_frame)
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(0)
        self.tableWidget.setRowCount(0)
        self.tableWidget.setAlternatingRowColors(True)
        self.gridLayout.addWidget(self.tableWidget, 0, 0, 1, 1)
        self.btn_frame = QtWidgets.QFrame(parent=self.widget)
        self.btn_frame.setGeometry(QtCore.QRect(30, 20, 1211, 80))
        self.btn_frame.setStyleSheet("")
        self.btn_frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.btn_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.btn_frame.setObjectName("btn_frame")
        self.decryptbtn = QtWidgets.QPushButton(parent=self.btn_frame)
        self.decryptbtn.setGeometry(QtCore.QRect(470, 20, 131, 41))
        self.decryptbtn.setStyleSheet("")
        self.decryptbtn.setObjectName("decryptbtn")
        self.sendbtn = QtWidgets.QPushButton(parent=self.btn_frame)
        self.sendbtn.setGeometry(QtCore.QRect(320, 20, 131, 41))
        self.sendbtn.setStyleSheet("")
        self.sendbtn.setObjectName("sendbtn")
        self.encryptbtn = QtWidgets.QPushButton(parent=self.btn_frame)
        self.encryptbtn.setGeometry(QtCore.QRect(170, 20, 131, 41))
        self.encryptbtn.setStyleSheet("")
        self.encryptbtn.setObjectName("encryptbtn")
        self.downloadbtn = QtWidgets.QPushButton(parent=self.btn_frame)
        self.downloadbtn.setGeometry(QtCore.QRect(620, 20, 131, 41))
        self.downloadbtn.setStyleSheet("")
        self.downloadbtn.setObjectName("downloadbtn")
        self.statelabel = QtWidgets.QLabel(parent=self.btn_frame)
        self.statelabel.setGeometry(QtCore.QRect(770, 20, 421, 41))
        self.statelabel.setObjectName("statelabel")
        self.importfilebtn = QtWidgets.QPushButton(parent=self.btn_frame)
        self.importfilebtn.setGeometry(QtCore.QRect(20, 20, 131, 41))
        self.importfilebtn.setStyleSheet("")
        self.importfilebtn.setObjectName("importfilebtn")
        self.progressBar = QtWidgets.QProgressBar(parent=self.btn_frame)
        self.progressBar.setGeometry(QtCore.QRect(770, 20, 421, 41))
        self.progressBar.setObjectName("progressBar")
        self.progressBar.setValue(0)
        self.progressBar.setMinimum(0)
        self.progressBar.setMaximum(100)

        csvdtgv.setCentralWidget(self.centralwidget)

        self.retranslateUi(csvdtgv)
        QtCore.QMetaObject.connectSlotsByName(csvdtgv)

        self.importfilebtn.clicked.connect(self.importfile)
        self.encryptbtn.clicked.connect(self.encryptdata)
        self.decryptbtn.clicked.connect(self.decryptdata)
        self.sendbtn.clicked.connect(self.send)
        self.downloadbtn.clicked.connect(self.downloadfile)

        self.encrypted_file_name = None
        self.prediction_file_name = None
        self.original_df = None

        # Connect to the SocketIO server
        sio.connect('http://127.0.0.1:5000')

        # Register the progress handler
        sio.on('progress', self.update_progress)

    def retranslateUi(self, csvdtgv):
        _translate = QtCore.QCoreApplication.translate
        csvdtgv.setWindowTitle(_translate("csvdtgv", "cryptotree"))
        self.NameSW.setText(_translate("csvdtgv", "CRYPTOTREE"))
        self.importfilebtn.setText(_translate("csvdtgv", "Choose File"))
        self.sendbtn.setText(_translate("csvdtgv", "Predict"))
        self.downloadbtn.setText(_translate("csvdtgv", "Download"))
        self.encryptbtn.setText(_translate("csvdtgv", "Encrypt"))
        self.decryptbtn.setText(_translate("csvdtgv", "Decrypt"))
        self.inputfilename.setText(_translate("csvdtgv", ""))
        self.statelabel.setText(_translate("csvdtgv", ""))
        self.progressBar.hide()
        
        for row in range(self.tableWidget.rowCount()):
            if row % 2 == 0:
                for column in range(self.tableWidget.columnCount()):
                    self.tableWidget.item(row, column).setBackground(QColor(224, 224, 224))
            else:
                for column in range(self.tableWidget.columnCount()):
                    self.tableWidget.item(row, column).setBackground(QColor(255, 255, 255))

    def update_progress(self, data):
        progress = data['progress']
        self.progressBar.setValue(progress)

    def importfile(self):
        file_filter = 'CSV Files (*.csv);;Excel Files (*.xls *.xlsx);;All Files (*)'
        response, _ = QFileDialog.getOpenFileName(
            parent=self.centralwidget,
            caption='Open CSV or Excel File',
            directory=os.getcwd(),
            filter=file_filter,
            initialFilter='CSV Files (*.csv)'
        )

        if response:
            self.tableWidget.clear()
            self.tableWidget.setRowCount(0)
            self.tableWidget.setColumnCount(0)
            self.inputfilename.setText(response)
            self.statelabel.setText("")
            _, file_extension = os.path.splitext(response)

            try:
                if file_extension.lower() == '.csv':
                    df = pd.read_csv(response)
                    self.statelabel.setText("Open file successfully.")
                elif file_extension.lower() in ['.xls', '.xlsx']:
                    df = pd.read_excel(response)
                    self.statelabel.setText("Open file successfully.")
                else:
                    self.statelabel.setText("Unsupported file format.")
                    return

                if df.empty:
                    self.statelabel.setText("The selected file is empty.")
                    return

                self.original_df = df
                df.fillna('', inplace=True)
                self.tableWidget.setRowCount(df.shape[0])
                self.tableWidget.setColumnCount(df.shape[1])
                self.tableWidget.setHorizontalHeaderLabels(df.columns)

                for row_index, row_data in df.iterrows():
                    for col_index, value in enumerate(row_data):
                        tableItem = QTableWidgetItem(str(value))
                        tableItem.setFlags(tableItem.flags() & ~Qt.ItemFlag.ItemIsEditable)
                        self.tableWidget.setItem(row_index, col_index, tableItem)

                self.tableWidget.resizeColumnsToContents()
                header = self.tableWidget.horizontalHeader()
            except Exception as e:
                self.statelabel.setText(f"Failed to load data: {e}")
        else:
            self.inputfilename.setText("Inputfile")
            self.statelabel.setText("")

    def encryptdata(self):
        try:
            # Gather data from the table
            data = []
            for row in range(self.tableWidget.rowCount()):
                row_data = []
                for column in range(self.tableWidget.columnCount()):
                    item = self.tableWidget.item(row, column)
                    row_data.append(item.text() if item else '')
                data.append(row_data)

            df = pd.DataFrame(data, columns=[self.tableWidget.horizontalHeaderItem(i).text() for i in range(self.tableWidget.columnCount())])
            df = df.apply(pd.to_numeric, errors='coerce').fillna(0)

            x = pipe.transform(df)
            data_encrypted = np.array([])

            self.progressBar.show()
            self.progressBar.setValue(0)

            for i, item in enumerate(tqdm(x)):
                ctx = homomorphic_featurizer.encrypt(item)
                data_encrypted = np.append(data_encrypted, ctx.to_string())

                progress = int((i + 1) / len(x) * 100)
                self.progressBar.setValue(progress)

            self.progressBar.hide()

            file_name, _ = QFileDialog.getSaveFileName(parent=self.centralwidget, caption="Save Encrypted Data", directory=os.getcwd(), filter="Numpy files (*.npy)")
            if file_name:
                np.save(file_name, data_encrypted)
                self.encrypted_file_name = file_name
                self.statelabel.setText(f"Encrypted Successfully")
            else:
                self.statelabel.setText("Save operation cancelled.")
        except Exception as e:
            self.progressBar.hide()
            self.statelabel.setText(f"Encryption failed: {e}")


    def decryptdata(self):
        try:
            file_name, _ = QFileDialog.getOpenFileName(parent=self.centralwidget, caption="Open Prediction File", directory=os.getcwd(), filter="Numpy files (*.npy)")
            if file_name:
                self.prediction_file_name = file_name

            if not self.prediction_file_name:
                self.statelabel.setText("No prediction file available. Perform prediction first.")
                return

            results = np.load(self.prediction_file_name)
            res = []

            self.progressBar.show()
            self.progressBar.setValue(0)

            for i, r in enumerate(results):
                ctx = context.from_cipher_str(r)
                ptx = seal.Plaintext()
                decryptor.decrypt(ctx, ptx)
                values = encoder.decode(ptx)[:2]
                homomorphic_pred = np.argmax(values)
                res.append(int(homomorphic_pred))  # Convert to integer

                progress = int((i + 1) / len(results) * 100)
                self.progressBar.setValue(progress)

            self.progressBar.hide()

            # Prepare decrypted results for display in the table
            decrypted_df = pd.DataFrame({'Original': self.original_df.iloc[:, 0], 'IsFraud': res})

            # Convert 'IsFraud' column to integers
            decrypted_df['IsFraud'] = decrypted_df['IsFraud'].astype(int)

            self.tableWidget.setColumnCount(decrypted_df.shape[1])
            self.tableWidget.setRowCount(decrypted_df.shape[0])
            self.tableWidget.setHorizontalHeaderLabels(decrypted_df.columns)

            for row_index, row_data in decrypted_df.iterrows():
                for col_index, value in enumerate(row_data):
                    tableItem = QTableWidgetItem(str(value))
                    tableItem.setFlags(tableItem.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    self.tableWidget.setItem(row_index, col_index, tableItem)

            self.statelabel.setText(f"Decryption successfully.")
        except Exception as e:
            self.progressBar.hide()
            self.statelabel.setText(f"Decryption failed: {e}")


    def send(self):
        self.statelabel.setText(f"Choose input file")
        file_name, _ = QFileDialog.getOpenFileName(parent=self.centralwidget, caption="Choose input file", directory=os.getcwd(), filter="Numpy files (*.npy)")
        if file_name:
            self.encrypted_file_name = file_name
            self.statelabel.setText(f"Choose folder to save output file")
            output_dir = QFileDialog.getExistingDirectory(parent=self.centralwidget, caption="Choose folder to save output file", directory=os.getcwd())

            if output_dir:
                self.progressBar.show()
                self.statelabel.setText(f"Predictting")
                with open(self.encrypted_file_name, 'rb') as f:
                    files = {'file': f}
                    data = {'output_dir': output_dir}
                    response = requests.post('http://localhost:5000/predict', files=files, data=data)

                if response.status_code == 200:
                    res_json = response.json()
                    output_file_path = res_json.get("output_file")
                    self.statelabel.setText(f"Prediction done.")
                    self.progressBar.hide()
                    
                else:
                    self.statelabel.setText(f"Error: {response.text}")
            else:
                self.statelabel.setText("Output directory selection cancelled.")
        else:
            self.statelabel.setText("File selection cancelled.")

    def downloadfile(self):
        file_name, _ = QFileDialog.getSaveFileName(parent=self.centralwidget, caption="Save CSV File", directory=os.getcwd(), filter="CSV Files (*.csv)")
        if file_name:
            try:
                with open(file_name, 'w', newline='') as csv_file:
                    writer = csv.writer(csv_file)
                    # Write header
                    header_labels = [self.tableWidget.horizontalHeaderItem(i).text() for i in range(self.tableWidget.columnCount())]
                    writer.writerow(header_labels)
                    # Write data
                    for row in range(self.tableWidget.rowCount()):
                        row_data = []
                        for column in range(self.tableWidget.columnCount()):
                            item = self.tableWidget.item(row, column)
                            row_data.append(item.text() if item else '')
                        writer.writerow(row_data)
                self.statelabel.setText(f"Download file successfully")
            except Exception as e:
                self.statelabel.setText(f"Failed to export data: {e}")
        else:
            self.statelabel.setText("Save operation cancelled.")

if __name__ == "__main__":
    # Khi tất cả các tệp đã có sẵn, chạy ứng dụng PyQt6
    app = QtWidgets.QApplication(sys.argv)
    csvdtgv = QtWidgets.QMainWindow()
    ui = Ui_csvdtgv()
    ui.setupUi(csvdtgv)
    csvdtgv.show()
    sys.exit(app.exec())
