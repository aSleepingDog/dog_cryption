#include <Qapplication>
#include <QWebEngineView>
#include <QMainWindow>
#include <QUrl>
#include <iostream>
#include <QObject>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QWebChannel>
#include <QWebEngineSettings>
#include <QWebEngineFileSystemAccessRequest>
#include <QFileDialog>
#include <QKeyEvent>

#include "../lib/dog_cryption.h"
#include "../extend/util.h";

work::taskPool taskPool(8);

work::taskPool* getTaskPool()
{
	return &taskPool;
}
/*
class ~Bridge : public QObject
{
	Q_OBJECT
public:
	explicit ~Bridge(QObject* parent = nullptr) : QObject(parent) {}

public slots:
	void receive(const QString& jsonStr);

signals:
	void send(const QString& jsonStr);
};

*/

class TaskInfoBridge : public QObject
{
	Q_OBJECT
public:
	explicit TaskInfoBridge(QObject* parent = nullptr) : QObject(parent) {}

public slots:
	void receive(const QJsonArray& json)
	{
		QJsonArray result;
		for (uint64_t i = 0; i < json.size(); i++)
		{
			QJsonObject task = json.at(i).toObject();
			work::taskInfo info = getTaskPool()->get_task_info(task["id"].toInt());
			QJsonObject taskInfo;
			taskInfo["id"] = QString::number(info.id);
			taskInfo["type"] = QString::fromStdString(info.type);
			if (info.status == 0)
			{
				taskInfo["status"] = "running";
				taskInfo["progress"] = QString::number(info.progress*100);
				taskInfo["time"] = QString::number(info.microSecond * (1.0f - info.progress) / info.progress);
			}
			else if (info.status == 1)
			{
				taskInfo["status"] = "success";
				taskInfo["time"] = QString::number(info.microSecond);
				if (task["type"] == "hash")
				{
					std::string stdResult;
					QString qResult;
					switch (task["outputCode"].toInt())
					{
					case DogData::Data::HEX:
					{
						bool isUpper = task["isUpper"].toBool();
						stdResult = info.result.getHexString(isUpper);
						qResult = QString::fromStdString(stdResult);
						taskInfo["result"] = qResult;
						break;
					}
					case DogData::Data::BASE64:
					{
						QChar qchar1 = task["outputChar1"].toString()[0];
						QChar qchar2 = task["outputChar2"].toString()[0];
						QChar qchar3 = task["outputChar3"].toString()[0];
						char char1 = qchar1.toLatin1();
						char char2 = qchar2.toLatin1();
						char char3 = qchar3.toLatin1();
                        stdResult = info.result.getBase64String(char1, char2, char3);
						qResult = QString::fromStdString(stdResult);
						taskInfo["result"] = qResult;
						break;
					}
					}
				}
				else
				{
					std::string stdResult = info.msg;
					QString qResult = QString::fromStdString(stdResult);
					taskInfo["result"] = qResult;
					taskInfo["msg"] = qResult;
				}
				
			}
			else if (info.status == -1)
			{
				taskInfo["status"] = "fail";
				taskInfo["error"] = QString::fromStdString(info.msg);
			}
			result.append(taskInfo);
		}
		// QString::fromUtf8(QJsonDocument(result).toJson(QJsonDocument::Compact).constData());
		//qDebug() << QString::fromUtf8(QJsonDocument(result).toJson(QJsonDocument::Compact).constData());
        emit send(result);
	}

signals:
	void send(const QJsonArray& jsons);
};

class FileChooseBridge : public QObject
{
	Q_OBJECT
public:
	explicit FileChooseBridge(QObject* parent = nullptr) : QObject(parent) {}

public slots:
	void receive(const QString& elemnetId)
	{
		QWidget* simple = new QWidget();
		QFileDialog* fileDialog = new QFileDialog(simple);
		fileDialog->setWindowTitle(QStringLiteral("选择文件"));
		fileDialog->setDirectory(QCoreApplication::applicationDirPath());
		fileDialog->setFileMode(QFileDialog::ExistingFile);
		fileDialog->setViewMode(QFileDialog::Detail);
		QString fileName;
		if (fileDialog->exec()) 
		{
			fileName = fileDialog->selectedFiles()[0];
		}
		//qDebug() << fileName;
		delete simple;
		QJsonObject result;
		result["path"] = fileName;
		result["id"] = elemnetId;
        emit send(QJsonDocument(result).toJson());
	}

signals:
	void send(const QString& jsonStr);
};

class DataTurnBridge : public QObject 
{
	Q_OBJECT
public:
	explicit DataTurnBridge(QObject* parent = nullptr) : QObject(parent) {}

public slots:
	void receive(const QString& jsonStr)
	{
		try
		{
			work::timer taskTimer;
			taskTimer.start();
			QJsonDocument doc = QJsonDocument::fromJson(jsonStr.toUtf8());
			QJsonObject args = doc.object();
			int inputTypeCode = args["inputTypeCode"].toInt();
			int outputTypeCode = args["outputTypeCode"].toInt();
			QString qvalue = args["value"].toString();
			QChar qchar1, qchar2, qchar3;
			if (inputTypeCode == DogData::Data::BASE64)
			{
				qchar1 = args["inputChar1"].toString()[0];
				qchar2 = args["inputChar2"].toString()[0];
				qchar3 = args["inputChar3"].toString()[0];
				qvalue.replace(qchar1, "+");
				qvalue.replace(qchar2, "/");
				qvalue.replace(qchar3, "=");
			}
			else if (inputTypeCode != DogData::Data::HEX && inputTypeCode != DogData::Data::UTF8)
			{
				//throw std::runtime_error("inputTypeCode error\n输入类型错误");
				throw std::runtime_error("输入类型错误");
			}
			std::string value = qvalue.toStdString();
			DogData::Data data(value, inputTypeCode);
			std::string result;
			switch (outputTypeCode)
			{
			case DogData::Data::UTF8:
			{
				result = data.getUTF8String();
				break;
			}
			case DogData::Data::BASE64:
			{
				qchar1 = args["outputChar1"].toString()[0];
				qchar2 = args["outputChar2"].toString()[0];
				qchar3 = args["outputChar3"].toString()[0];
				char char1 = qchar1.toLatin1();
				char char2 = qchar2.toLatin1();
				char char3 = qchar3.toLatin1();
				result = data.getBase64String(char1, char2, char3);
				break;
			}
			case DogData::Data::HEX:
			{
				bool isUpper = args["isUpper"].toBool();
				result = data.getHexString(isUpper);
				break;
			}
			default:
			{
				throw std::runtime_error("输出类型错误");
			}
			}
			taskTimer.end();
			QJsonObject json;
			json["result"] = QString::fromStdString(result);
			json["time"] = taskTimer.getTime();
			json["status"] = true;
			emit this->send(QJsonDocument(json).toJson());
		}
		catch (const std::exception& e)
		{
			QJsonObject json;
			json["status"] = false;
			json["error"] = QString::fromStdString(e.what());
			emit this->send(QJsonDocument(json).toJson());
		}
	}

signals:
	void send(const QString& jsonStr);
};

class HashBridge : public QObject
{
	Q_OBJECT
public:
	explicit HashBridge(QObject* parent = nullptr) : QObject(parent) {}
public slots:
	void receive(const QString& jsonStr, const QString& str2)
	{
		try
		{
			QJsonDocument doc = QJsonDocument::fromJson(jsonStr.toUtf8());
			QJsonObject args = doc.object();
			int inputTypeCode = args["inputTypeCode"].toInt();
			if (inputTypeCode != 3)
			{
				work::timer taskTimer;
				DogData::Data inputData;
				QString qvalue = args["value"].toString();
				QChar qchar1, qchar2, qchar3;
				if (inputTypeCode == DogData::Data::BASE64)
				{
					qchar1 = args["inputChar1"].toString()[0];
					qchar2 = args["inputChar2"].toString()[0];
					qchar3 = args["inputChar3"].toString()[0];
					qvalue.replace(qchar1, "+");
					qvalue.replace(qchar2, "/");
					qvalue.replace(qchar3, "=");
				}
				else if (inputTypeCode != DogData::Data::HEX && inputTypeCode != DogData::Data::UTF8)
				{
					//throw std::runtime_error("inputTypeCode error\n输入类型错误");
					throw std::runtime_error("输入类型错误");
				}
				std::string value = qvalue.toStdString();
				inputData = DogData::Data(value, inputTypeCode);
				QString qhashType = str2;
				std::string hashType = qhashType.toStdString();
				DogHash::hash_crypher hashCrypher(hashType);
				taskTimer.start();
				DogData::Data resultData = hashCrypher.getDataHash(inputData);
				taskTimer.end();
				std::string result;
				int outputTypeCode = args["outputTypeCode"].toInt();
				
				switch (outputTypeCode)
				{
				case DogData::Data::UTF8:
				{
					result = resultData.getUTF8String();
					break;
				}
				case DogData::Data::BASE64:
				{
					qchar1 = args["outputChar1"].toString()[0];
					qchar2 = args["outputChar2"].toString()[0];
					qchar3 = args["outputChar3"].toString()[0];
					char char1 = qchar1.toLatin1();
					char char2 = qchar2.toLatin1();
					char char3 = qchar3.toLatin1();
					result = resultData.getBase64String(char1, char2, char3);
					break;
				}
				case DogData::Data::HEX:
				{
					bool isUpper = args["isUpper"].toBool();
					result = resultData.getHexString(isUpper);
					break;
				}
				default:
				{
					//throw std::runtime_error("outputTypeCode error\n输出类型错误");
					throw std::runtime_error("输出类型错误");
				}
				}
				
				QJsonObject json;
				json["type"] = "text";
				json["result"] = QString::fromStdString(result);
				json["time"] = taskTimer.getTime();
				json["status"] = true;
				emit this->send(QJsonDocument(json).toJson());
			}
			else
			{
				QString qpath = args["value"].toString();
				std::string path = qpath.toStdString();
				QString qhashType = str2;
				std::string hashType = qhashType.toStdString();
				uint64_t id = getTaskPool()->add_hash_task(hashType, path);
				if (id == UINT64_MAX) 
				{ 
					//throw std::runtime_error("to much tasks,must be 8 tasks is running");
					throw std::runtime_error("当前运行的任务过多,最多8个");
				}
				QJsonObject json;
				QString output = "";
				switch (args["outputTypeCode"].toInt())
				{
				case DogData::Data::BASE64:
				{
					QChar qchar1 = args["outputChar1"].toString()[0];
					QChar qchar2 = args["outputChar2"].toString()[0];
					QChar qchar3 = args["outputChar3"].toString()[0];
					json["outputChar1"] = qchar1.toLatin1();
					json["outputChar2"] = qchar2.toLatin1();
					json["outputChar3"] = qchar3.toLatin1();
					output = QString("base64(%1%2%3)").arg(qchar1).arg(qchar2).arg(qchar3);
					break;
				}
				case DogData::Data::HEX:
				{
					if (args["isUpper"].toBool())
					{
						output = "hex大写";
						json["isUpper"] = true;
					}
					else
					{
						output = "hex小写";
						json["isUpper"] = false;
					}
					break;
				}
				}
				json["id"] = QString::number(id);
				json["status"] = true;
				json["type"] = "file";
				json["hash"] = qhashType;
				json["file"] = qpath;
				json["output"] = output;
				json["outputCode"] = args["outputTypeCode"].toInt();
				emit this->send(QJsonDocument(json).toJson());
			}
		}
		catch (const std::exception& e)
		{
			QJsonObject json;
			json["status"] = false;
			json["error"] = QString::fromStdString(e.what());
			emit this->send(QJsonDocument(json).toJson());
		}
	}
signals:
	void send(const QString& jsonStr);
};

class EncryptBridge : public QObject
{
	Q_OBJECT
public:
	explicit EncryptBridge(QObject* parent = nullptr) : QObject(parent) {};
public slots:
	void receive(const QJsonObject& json1, const QJsonObject& json2, const QJsonObject& json3)
	{
		QJsonObject jplainConfig = json1;
		QJsonObject jcryptionConfig = json2;
		QJsonObject jkeyConfig = json3;
		try
		{
			int plainInputTypeCode = jplainConfig["inputTypeCode"].toInt();
			if (plainInputTypeCode != 3)
			{
				work::timer taskTimer;
				DogData::Data plainData;
				QString qplainValue = jplainConfig["value"].toString();
				QChar qchar1, qchar2, qchar3;
				if (plainInputTypeCode == DogData::Data::BASE64)
				{
					qchar1 = jplainConfig["inputChar1"].toString()[0];
					qchar2 = jplainConfig["inputChar2"].toString()[0];
					qchar3 = jplainConfig["inputChar3"].toString()[0];
					qplainValue.replace(qchar1, "+");
					qplainValue.replace(qchar2, "/");
					qplainValue.replace(qchar3, "=");
				}
				else if (plainInputTypeCode != DogData::Data::HEX && plainInputTypeCode != DogData::Data::UTF8)
				{
					//throw std::runtime_error("plain inputTypeCode error\n明文输入类型错误");
					throw std::runtime_error("明文输入类型错误");
				}
				std::string plainValue = qplainValue.toStdString();
				plainData = DogData::Data(plainValue, plainInputTypeCode);

				QString qalgorithm = jcryptionConfig["algorithm"].toString();
				std::string algorithm = qalgorithm.toStdString();
				uint64_t blockSize = jcryptionConfig["blockSize"].toInt();
                uint64_t keySize = jcryptionConfig["keySize"].toInt();
				QString qmode = jcryptionConfig["mode"].toString();
				std::string mode = qmode.toStdString();
                QString qpadding = jcryptionConfig["padding"].toString();
				std::string padding = qpadding.toStdString();
				bool isPadding = jcryptionConfig["isPadding"].toBool();
				DogCryption::cryption_config cryptConfig(
					algorithm, blockSize, keySize, 
					padding,
					mode,true,isPadding,false
				);
				DogCryption::cryptor cryptor(cryptConfig);

				int keyInputTypeCode = jkeyConfig["inputTypeCode"].toInt();
				QString qkeyValue = jkeyConfig["value"].toString();
				if (keyInputTypeCode == DogData::Data::BASE64)
				{
					qchar1 = jkeyConfig["inputChar1"].toString()[0];
					qchar2 = jkeyConfig["inputChar2"].toString()[0];
					qchar3 = jkeyConfig["inputChar3"].toString()[0];
					qkeyValue.replace(qchar1, "+");
					qkeyValue.replace(qchar2, "/");
					qkeyValue.replace(qchar3, "=");
				}
				else if (keyInputTypeCode != DogData::Data::HEX && keyInputTypeCode != DogData::Data::UTF8)
				{
					//throw std::runtime_error("key inputTypeCode error\n密钥输入类型错误");
					throw std::runtime_error("密钥输入类型错误");
				}
				std::string keyValue = qkeyValue.toStdString();
                DogData::Data keyData(keyValue, keyInputTypeCode);
				cryptor.set_key(keyData);

				taskTimer.start();
                auto cryptDataPair = cryptor.encrypt(plainData);
				taskTimer.end();
				DogData::Data cryptData = cryptDataPair.first + cryptDataPair.second;


				int outputTypeCode = jplainConfig["outputTypeCode"].toInt();
				std::string result;
				switch (outputTypeCode)
				{
				case DogData::Data::UTF8:
				{
					result = cryptData.getUTF8String();
					break;
				}
				case DogData::Data::BASE64:
				{
					qchar1 = jplainConfig["outputChar1"].toString()[0];
					qchar2 = jplainConfig["outputChar2"].toString()[0];
					qchar3 = jplainConfig["outputChar3"].toString()[0];
					char char1 = qchar1.toLatin1();
					char char2 = qchar2.toLatin1();
					char char3 = qchar3.toLatin1();
					result = cryptData.getBase64String(char1, char2, char3);
					break;
				}
				case DogData::Data::HEX:
				{
					bool isUpper = jplainConfig["isUpper"].toBool();
					result = cryptData.getHexString(isUpper);
					break;
				}
				default:
				{
					//throw std::runtime_error("outputTypeCode error\n输出类型错误");
					throw std::runtime_error("输出类型错误");
				}
				}
				QJsonObject json;
				json["type"] = "text";
				json["status"] = true;
				json["result"] = QString::fromStdString(result);
				json["time"] = taskTimer.getTime();
				emit this->send(QJsonDocument(json).toJson());
			}
			else
			{
				QString qInputPath = json1["value"].toString();
				std::string inputpath = qInputPath.toStdString();
				QString qOutputPath = qInputPath + ".CRYPT";
				std::string outputpath = inputpath + ".CRYPT";

				QString qalgorithm = jcryptionConfig["algorithm"].toString();
				std::string algorithm = qalgorithm.toStdString();
				uint64_t blockSize = jcryptionConfig["blockSize"].toInt();
				uint64_t keySize = jcryptionConfig["keySize"].toInt();
				QString qmode = jcryptionConfig["mode"].toString();
				std::string mode = qmode.toStdString();
				QString qpadding = jcryptionConfig["padding"].toString();
				std::string padding = qpadding.toStdString();
				bool isPadding = jcryptionConfig["isPadding"].toBool();
				DogCryption::cryption_config cryptConfig(
					algorithm, blockSize, keySize,
					padding,
					mode, true, isPadding, false
				);

				int keyInputTypeCode = jkeyConfig["inputTypeCode"].toInt();
				QString qkeyValue = jkeyConfig["value"].toString();
				if (keyInputTypeCode == DogData::Data::BASE64)
				{
					QString qchar1 = jkeyConfig["inputChar1"].toString()[0];
					QString qchar2 = jkeyConfig["inputChar2"].toString()[0];
					QString qchar3 = jkeyConfig["inputChar3"].toString()[0];
					qkeyValue.replace(qchar1, "+");
					qkeyValue.replace(qchar2, "/");
					qkeyValue.replace(qchar3, "=");
				}
				else if (keyInputTypeCode != DogData::Data::HEX && keyInputTypeCode != DogData::Data::UTF8)
				{
					//throw std::runtime_error("key inputTypeCode error\n密钥输入类型错误");
					throw std::runtime_error("密钥输入类型错误");
				}
				std::string keyValue = qkeyValue.toStdString();
				DogData::Data keyData(keyValue, keyInputTypeCode);

				bool withConfig = jcryptionConfig["withConfig"].toBool();

				uint64_t id = getTaskPool()->add_encrypt_task(cryptConfig, keyData, inputpath, withConfig, outputpath);
				if (id == UINT64_MAX)
				{
					//throw std::runtime_error("to much tasks,must be 8 tasks is running");
					throw std::runtime_error("当前运行的任务过多,最多8个");
				}

				QJsonObject json;
				json["id"] = QString::number(id);
				json["status"] = true;
				json["type"] = "file";
				json["cryption"] = QString::fromStdString(cryptConfig.to_string());
				json["inputFile"] = qInputPath;
				json["outputFile"] = qOutputPath;
				emit this->send(QJsonDocument(json).toJson());
			}

		}
		catch (const std::exception& e)
		{
			QJsonObject json;
			json["status"] = false;
			json["error"] = QString::fromStdString(e.what());
			emit this->send(QJsonDocument(json).toJson());
		}
	}
signals:
	void send(const QString& jsonStr);
};

class DecryptBridge : public QObject
{
	Q_OBJECT
public:
	explicit DecryptBridge(QObject* parent = nullptr) : QObject(parent) {};
public slots:
	void receive(const QJsonObject& json1, const QJsonObject& json2, const QJsonObject& json3)
	{
		QJsonObject jcryptConfig = json1;
		QJsonObject jcryptionConfig = json2;
		QJsonObject jkeyConfig = json3;
		try
		{
			int plainInputTypeCode = jcryptConfig["inputTypeCode"].toInt();
			if (plainInputTypeCode != 3)
			{
				work::timer taskTimer;
				DogData::Data cryptData;
				QString qcryptValue = jcryptConfig["value"].toString();
				QChar qchar1, qchar2, qchar3;
				if (plainInputTypeCode == DogData::Data::BASE64)
				{
					qchar1 = jcryptConfig["inputChar1"].toString()[0];
					qchar2 = jcryptConfig["inputChar2"].toString()[0];
					qchar3 = jcryptConfig["inputChar3"].toString()[0];
					qcryptValue.replace(qchar1, "+");
					qcryptValue.replace(qchar2, "/");
					qcryptValue.replace(qchar3, "=");
				}
				else if (plainInputTypeCode != DogData::Data::HEX && plainInputTypeCode != DogData::Data::UTF8)
				{
					//throw std::runtime_error("plain inputTypeCode error\n明文输入类型错误");
					throw std::runtime_error("明文输入类型错误");
				}
				std::string plainValue = qcryptValue.toStdString();
				cryptData = DogData::Data(plainValue, plainInputTypeCode);

				QString qalgorithm = jcryptionConfig["algorithm"].toString();
				std::string algorithm = qalgorithm.toStdString();
				uint64_t blockSize = jcryptionConfig["blockSize"].toInt();
				uint64_t keySize = jcryptionConfig["keySize"].toInt();
				QString qmode = jcryptionConfig["mode"].toString();
				std::string mode = qmode.toStdString();
				QString qpadding = jcryptionConfig["padding"].toString();
				std::string padding = qpadding.toStdString();
				bool isPadding = jcryptionConfig["isPadding"].toBool();
				DogCryption::cryption_config cryptConfig(
					algorithm, blockSize, keySize,
					padding,
					mode, true, isPadding, false
				);
				DogCryption::cryptor cryptor(cryptConfig);

				int keyInputTypeCode = jkeyConfig["inputTypeCode"].toInt();
				QString qkeyValue = jkeyConfig["value"].toString();
				if (keyInputTypeCode == DogData::Data::BASE64)
				{
					qchar1 = jkeyConfig["inputChar1"].toString()[0];
					qchar2 = jkeyConfig["inputChar2"].toString()[0];
					qchar3 = jkeyConfig["inputChar3"].toString()[0];
					qkeyValue.replace(qchar1, "+");
					qkeyValue.replace(qchar2, "/");
					qkeyValue.replace(qchar3, "=");
				}
				else if (keyInputTypeCode != DogData::Data::HEX && keyInputTypeCode != DogData::Data::UTF8)
				{
					//throw std::runtime_error("key inputTypeCode error\n密钥输入类型错误");
					throw std::runtime_error("密钥输入类型错误");
				}
				std::string keyValue = qkeyValue.toStdString();
				DogData::Data keyData(keyValue, keyInputTypeCode);
				cryptor.set_key(keyData);

				DogData::Data cryptiv = cryptData.sub_by_len(0, cryptConfig.block_size);
				DogData::Data cryptmid = cryptData.sub_by_pos(cryptConfig.block_size, cryptData.size());
				taskTimer.start();
				DogData::Data plainData = cryptor.decrypt(cryptiv, cryptmid);
				taskTimer.end();


				int outputTypeCode = jcryptConfig["outputTypeCode"].toInt();
				std::string result;
				switch (outputTypeCode)
				{
				case DogData::Data::UTF8:
				{
					result = plainData.getUTF8String();
					break;
				}
				case DogData::Data::BASE64:
				{
					qchar1 = jcryptConfig["outputChar1"].toString()[0];
					qchar2 = jcryptConfig["outputChar2"].toString()[0];
					qchar3 = jcryptConfig["outputChar3"].toString()[0];
					char char1 = qchar1.toLatin1();
					char char2 = qchar2.toLatin1();
					char char3 = qchar3.toLatin1();
					result = plainData.getBase64String(char1, char2, char3);
					break;
				}
				case DogData::Data::HEX:
				{
					bool isUpper = jcryptConfig["isUpper"].toBool();
					result = plainData.getHexString(isUpper);
					break;
				}
				default:
				{
					//throw std::runtime_error("outputTypeCode error\n输出类型错误");
					throw std::runtime_error("输出类型错误");
				}
				}
				QJsonObject json;
				json["type"] = "text";
				json["status"] = true;
				json["result"] = QString::fromStdString(result);
				json["time"] = taskTimer.getTime();
				emit this->send(QJsonDocument(json).toJson());
			}
			else
			{
				QString qInputPath = json1["value"].toString();
				std::string inputpath = qInputPath.toStdString();
				QString qOutputPath = qInputPath + ".PLAIN";
				std::string outputpath = inputpath + ".PLAIN";

				QString qalgorithm = jcryptionConfig["algorithm"].toString();
				std::string algorithm = qalgorithm.toStdString();
				uint64_t blockSize = jcryptionConfig["blockSize"].toInt();
				uint64_t keySize = jcryptionConfig["keySize"].toInt();
				QString qmode = jcryptionConfig["mode"].toString();
				std::string mode = qmode.toStdString();
				QString qpadding = jcryptionConfig["padding"].toString();
				std::string padding = qpadding.toStdString();
				bool isPadding = jcryptionConfig["isPadding"].toBool();
				DogCryption::cryption_config cryptConfig(
					algorithm, blockSize, keySize,
					padding,
					mode, true, isPadding, false
				);

				int keyInputTypeCode = jkeyConfig["inputTypeCode"].toInt();
				QString qkeyValue = jkeyConfig["value"].toString();
				if (keyInputTypeCode == DogData::Data::BASE64)
				{
					QString qchar1 = jkeyConfig["inputChar1"].toString()[0];
					QString qchar2 = jkeyConfig["inputChar2"].toString()[0];
					QString qchar3 = jkeyConfig["inputChar3"].toString()[0];
					qkeyValue.replace(qchar1, "+");
					qkeyValue.replace(qchar2, "/");
					qkeyValue.replace(qchar3, "=");
				}
				else if (keyInputTypeCode != DogData::Data::HEX && keyInputTypeCode != DogData::Data::UTF8)
				{
					//throw std::runtime_error("key inputTypeCode error\n密钥输入类型错误");
					throw std::runtime_error("密钥输入类型错误");
				}
				std::string keyValue = qkeyValue.toStdString();
				DogData::Data keyData(keyValue, keyInputTypeCode);

				bool withConfig = jcryptionConfig["withConfig"].toBool();

				uint64_t id = getTaskPool()->add_decrypt_task(cryptConfig, keyData, inputpath, withConfig, outputpath);
				if (id == UINT64_MAX) 
				{
					//throw std::runtime_error("to much tasks,must be 8 tasks is running");
					throw std::runtime_error("当前运行的任务过多,最多8个");
				}

				QJsonObject json;
				json["id"] = QString::number(id);
				json["status"] = true;
				json["type"] = "file";
				json["cryption"] = QString::fromStdString(cryptConfig.to_string());
				json["inputFile"] = qInputPath;
				json["outputFile"] = qOutputPath;
				emit this->send(QJsonDocument(json).toJson());
			}

		}
		catch (const std::exception& e)
		{
			QJsonObject json;
			json["status"] = false;
			json["error"] = QString::fromStdString(e.what());
			emit this->send(QJsonDocument(json).toJson());
		}
	}
signals:
	void send(const QString& jsonStr);
};

class cryptionWindow : public QMainWindow
{
	Q_OBJECT

	QWebEngineView *view;
	QWebEngineView *devTools;

	TaskInfoBridge *taskInfoBridge;
	DataTurnBridge *dataTurnBridge;
	HashBridge *hashBridge;
	FileChooseBridge *fileChooseBridge;
	EncryptBridge *encryptBridge;
	DecryptBridge* decryptBridge;

public:
	cryptionWindow(QWidget* parent = nullptr) : QMainWindow(parent)
	{
		//QString oripath = QCoreApplication::applicationDirPath();
		//auto oripaths = oripath.split("/");
		////qDebug() << oripaths;
		//QString path = oripaths[0] + "/" + oripaths[1] + "/" + oripaths[2] + "/";
		////qDebug() << path + "src/win/home.html";
		qDebug() << QCoreApplication::applicationDirPath() + "/page/home.html";
		QUrl url = QUrl::fromLocalFile(QCoreApplication::applicationDirPath() + "/page/home.html");
		view = new QWebEngineView(this);
		QWebChannel* channel = new QWebChannel(this);

		taskInfoBridge = new TaskInfoBridge(this);
		dataTurnBridge = new DataTurnBridge(this);
		hashBridge = new HashBridge(this);
		fileChooseBridge = new FileChooseBridge(this);
		encryptBridge = new EncryptBridge(this);
		decryptBridge = new DecryptBridge(this);

		channel->registerObject("taskInfoBridge", taskInfoBridge);
		channel->registerObject("dataTurnBridge", dataTurnBridge);
		channel->registerObject("hashBridge", hashBridge);
		channel->registerObject("fileChooseBridge", fileChooseBridge);
		channel->registerObject("encryptBridge", encryptBridge);
		channel->registerObject("decryptBridge", decryptBridge);

		QObject::connect
		(
			dataTurnBridge, &DataTurnBridge::send, [this](const QVariant& jsonStr) ->void
			{
				this->view->page()->runJavaScript(QString("setDataResult(%1)").arg(jsonStr.toString()));
			}
		);
		QObject::connect
		(
			hashBridge, &HashBridge::send, [this](const QVariant& jsonStr) ->void
			{
				this->view->page()->runJavaScript(QString("setHashResult(%1)").arg(jsonStr.toString()));
			}
		);
		QObject::connect
		(
			fileChooseBridge, &FileChooseBridge::send, [this](const QVariant& jsonStr) ->void
			{
				this->view->page()->runJavaScript(QString("updateFile(%1)").arg(jsonStr.toString()));
			}
		);
		QObject::connect
		(
			taskInfoBridge, &TaskInfoBridge::send, [this](const QJsonArray& jsons) ->void
			{
				this->view->page()->runJavaScript(QString("updateTaskStatus(%1)").arg(QJsonDocument(jsons).toJson()));
			}
		);
		QObject::connect
		(
			encryptBridge, &EncryptBridge::send, [this](const QVariant& jsonStr) ->void
			{
				this->view->page()->runJavaScript(QString("setEncryptResult(%1)").arg(jsonStr.toString()));
			}
		);
		QObject::connect
		(
			decryptBridge, &DecryptBridge::send, [this](const QVariant& jsonStr) ->void
			{
				this->view->page()->runJavaScript(QString("setDecryptResult(%1)").arg(jsonStr.toString()));
			}
		);


		view->page()->setWebChannel(channel);
		view->page()->settings()->setAttribute(QWebEngineSettings::LocalStorageEnabled, true);
		devTools = new QWebEngineView(this);
		devTools->resize(1200, 400);
        setCentralWidget(view);
		devTools->setVisible(false);
		view->load(url);
		view->page()->setDevToolsPage(devTools->page());
		view->resize(1200, 750);
		this->resize(1200, 750);
	}


protected:
	void keyPressEvent(QKeyEvent* event) override 
	{
		/*
		if ((event->modifiers() & (Qt::ControlModifier | Qt::ShiftModifier)) == (Qt::ControlModifier | Qt::ShiftModifier)
			&& event->key() == Qt::Key_I) 
		{
			devTools->show();
			devTools->move(0, 350);
		}
		else if (event->key() == Qt::Key_Delete)
		{
			devTools->hide();
		}
		*/
	}

	void closeEvent(QCloseEvent* event) override
	{
        QMainWindow::closeEvent(event);
		event->accept();
		deleteLater();
	}
};

int main(int argc, char* argv[])
{
	QApplication app(argc, argv);
	
	cryptionWindow *window = new cryptionWindow();
	window->show();

	return app.exec();
}

#include "qtwin.moc"