#include <iostream>

#include <QUrl>
#include <QPoint>
#include <QStyle>
#include <QLabel>
#include <QWidget>
#include <QObject>
#include <QMimeData>
#include <QKeyEvent>
#include <QDropEvent>
#include <QJsonArray>
#include <QClipboard>
#include <QJsonObject>
#include <QFileDialog>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QMessageBox>
#include <QWebChannel>
#include <Qapplication>
#include <QJsonDocument>
#include <QWebEngineView>
#include <QGuiApplication>
#include <QDragEnterEvent>
#include <QWebEngineSettings>
#include <QWebEngineFileSystemAccessRequest>

#include "../lib/dog_cryption.h"
#include "../extend/util.h"

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

work::TaskPool* task_pool = nullptr;

bool isInt(QJsonValue n)
{
	if (!n.isDouble())
	{
		return false;
	}
	double m = n.toDouble();
	return m == ((uint64_t)m) * 1.0;
}
uint64_t toInt(QJsonValue n)
{
	if (!isInt(n))
	{
		throw std::runtime_error("not int");
	}
	return n.toDouble();
}

class FileBridge : public QObject
{
	Q_OBJECT
public:
	explicit FileBridge(QObject * parent = nullptr) : QObject(parent) {}

public slots:
	void open(const QString& jsonstr)
	{
		QJsonDocument doc = QJsonDocument::fromJson(jsonstr.toUtf8());
		QJsonObject json = doc.object();
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
		if(!fileName.isEmpty()){
			QJsonObject result;
			result["filePath"] = fileName;
			result["id"] = json["id"];
			send(QJsonDocument(result).toJson());
		}

	};
public slots:
	void save(const QString& jsonstr)
	{
		QJsonDocument doc = QJsonDocument::fromJson(jsonstr.toUtf8());
		QJsonObject json = doc.object();
		QString originPath = "";
		if (!json["path"].isNull() && !json["path"].isUndefined() && !json["path"].toString().isEmpty())
		{
			//qDebug() << json["path"].toString();
            originPath = json["path"].toString();
		}
		QString fileName = QFileDialog::getSaveFileName(nullptr, tr("另存为"), originPath, tr("所有文件 (*)"));
		//qDebug() << fileName;
		if (!fileName.isEmpty()) {
			QJsonObject result;
			result["dirPath"] = fileName;
			result["id"] = json["id"];
			send_save(QJsonDocument(result).toJson());
		}
	}
public slots:
	void remove(const QString& jsonstr)
	{
		QJsonDocument doc = QJsonDocument::fromJson(jsonstr.toUtf8());
		QJsonObject json = doc.object();
		QJsonObject result;
		std::string input = json["path"].toString().toStdString();
		result["id"] = json["id"];
		std::filesystem::path path(input);
		if (!std::filesystem::exists(path))
		{
			result["code"] = 1;
			result["msg"] = "文件不存在";
			emit(send_remove(QJsonDocument(result).toJson()));
			return;
		}
		if (!std::filesystem::remove(path))
		{
			result["code"] = 1;
			result["msg"] = "文件不存在";
			emit(send_remove(QJsonDocument(result).toJson()));
			return;
		}
		else
		{
			result["code"] = 0;
			result["msg"] = "删除成功";
			emit(send_remove(QJsonDocument(result).toJson()));
			return;
		}
	}

signals:
	void send(const QString& jsonStr);
signals:
	void send_save(const QString& jsonStr);
signals:
	void send_remove(const QString& jsonStr);
};
class CopyBridge : public QObject
{
	Q_OBJECT
public:
	explicit CopyBridge(QObject* parent = nullptr) : QObject(parent) {}

public slots:
	void receive(const QString& str)
	{
		QGuiApplication::clipboard()->setText(str);
		QJsonObject result;
		result["code"] = 0;
		result["msg"] = "复制成功";
		//receive(QJsonDocument(result).toJson());
		emit send(QJsonDocument(result).toJson());
	}

signals:
	void send(const QString& jsonStr);
};

class HashListBridge : public QObject
{
	Q_OBJECT
public:
	explicit HashListBridge(QObject* parent = nullptr) : QObject(parent) {}

public slots:
	void receive()
	{
		QJsonArray hash_list;
		for (auto& hash : dog_hash::list)
		{
			QJsonObject single_hash;
			single_hash["name"] = QString::fromStdString(hash.name);
			single_hash["region"] = QString::fromStdString(hash.region);
			hash_list.append(single_hash);
		}
		emit send(hash_list);
	};

signals:
	void send(const QJsonArray& jsons);
};

class PaddingListBridge : public QObject
{
	Q_OBJECT
public:
	explicit PaddingListBridge(QObject * parent = nullptr) : QObject(parent) {}

public slots:
	void receive()
	{
		QJsonArray padding_list;
		for (auto& padding : dog_cryption::padding::list)
		{
			QJsonObject single_padding;
			single_padding["name"] = QString::fromStdString(padding.name_);
			single_padding["code"] = padding.code_;
			padding_list.append(single_padding);
		}
		emit send(padding_list);
	}

signals:
	void send(const QJsonArray& jsons);
};
class ModeListBridge : public QObject
{
	Q_OBJECT
public:
	explicit ModeListBridge(QObject* parent = nullptr) : QObject(parent) {}

public slots:
	void receive()
	{
		QJsonArray mode_list;
		for (auto& mode : dog_cryption::mode::list)
		{
			QJsonObject single_mode;
			single_mode["name"] = QString::fromStdString(mode.name_);
			single_mode["code"] = mode.code_;
			single_mode["forceIv"] = mode.force_iv_;
			single_mode["forcePadding"] = mode.force_padding_;
			single_mode["forceShift"] = mode.force_shift_;
			mode_list.append(single_mode);
		}
		emit send(mode_list);
	}

signals:
	void send(const QJsonArray& jsonStr);
};
class AlgorithmListBridge : public QObject
{
	Q_OBJECT
public:
	explicit AlgorithmListBridge(QObject* parent = nullptr) : QObject(parent) {}

public slots:
	void receive()
	{
		QJsonArray algorithm_list;
		for (auto& algorithm : dog_cryption::Algorithm_list)
		{
			QJsonObject single_algorithm;
			single_algorithm["name"] = QString::fromStdString(algorithm.name);
			single_algorithm["blockSizeRegion"] = QString::fromStdString(algorithm.block_size_region);
			single_algorithm["keySizeRegion"] = QString::fromStdString(algorithm.key_size_region);
			algorithm_list.append(single_algorithm);
		}
		emit send(algorithm_list);
	}

signals:
	void send(const QJsonArray& jsonStr);
};

class ExchangeBridge : public QObject
{
	Q_OBJECT
public:
	explicit ExchangeBridge(QObject* parent = nullptr) : QObject(parent) {}
public slots:
	void receive(const QString& jsonstr)
	{
		QJsonDocument doc = QJsonDocument::fromJson(jsonstr.toUtf8());
		QJsonObject json = doc.object();
		QJsonObject result;
		dog_data::Data data;
		if (json["input"].toString().isEmpty())
		{
			result["code"] = 1;
			result["msg"] = "请输入数据";
			emit send(QJsonDocument(result).toJson());
			return;
		}
		std::string input = json["input"].toString().toStdString();
		if (json["inputType"].isNull() || json["inputType"].isUndefined() || !isInt(json["inputType"]))
		{
			result["code"] = 1;
			result["msg"] = "请选择输入类型";
			emit send(QJsonDocument(result).toJson());
			return;
		}
		try
		{
			work::Timer t;
			t.start();
			data = dog_data::Data(input, toInt(json["inputType"]));
			t.end();
			result["time"] = t.get_time();
		}
		catch (std::exception& e)
		{
			result["code"] = 1;
			result["msg"] = "内部错误,请保留日志并联系开发人员"+QString::fromStdString(e.what());
			emit send(QJsonDocument(result).toJson());
			return;
		}
		
		if (json["outputType"].isNull() || json["outputType"].isUndefined() || !isInt(json["outputType"]))
		{
			result["code"] = 1;
			result["msg"] = "请选择输出类型";
			emit send(QJsonDocument(result).toJson());
			return;
		}
		switch (toInt(json["outputType"]))
		{
		case 0:
		{
			work::Timer t;
			t.start();
			result["res"] = QString::fromStdString(data.getUTF8String());
			t.end();
			result["time"] = result["time"].toDouble() + t.get_time();
			break;
		}
		case 1:
		{
			if (json["replace0"].isNull() || json["replace0"].isUndefined()
				|| json["replace1"].isNull() || json["replace1"].isUndefined()
				|| json["replace2"].isNull() || json["replace2"].isUndefined())
			{
				result["code"] = 1;
				result["msg"] = "请输入替换字符";
			}
			else if (json["replace0"].toString() == json["replace1"].toString()
				|| json["replace0"].toString() == json["replace2"].toString()
				|| json["replace1"].toString() == json["replace2"].toString())
			{
				result["code"] = 1;
				result["msg"] = "替换字符不能相同";
			}
			char replace0 = json["replace0"].toString().toStdString()[0];
			char replace1 = json["replace1"].toString().toStdString()[0];
			char replace2 = json["replace2"].toString().toStdString()[0];
			work::Timer t;
			t.start();
			result["res"] = QString::fromStdString(data.getBase64String(replace0, replace1, replace2));
			t.end();
			result["time"] = result["time"].toDouble() + t.get_time();
			break;
		}
		case 2:
		{
			if (json["upper"].isNull() || json["upper"].isUndefined())
			{
				result["code"] = 1;
				result["msg"] = "请指定大小写";
				emit send(QJsonDocument(result).toJson());
				return;
			}
			else if (!json["upper"].isBool())
			{
				result["code"] = 1;
				result["msg"] = "请正确指定大小写";
				emit send(QJsonDocument(result).toJson());
				return;
			}
			bool upper = json["upper"].toBool();
			work::Timer t;
			t.start();
			result["res"] = QString::fromStdString(data.getHexString(upper));
			t.end();
			result["time"] = result["time"].toDouble() + t.get_time();
			break;
		}
		default:
		{
			result["code"] = 1;
			result["msg"] = "输出类型错误,仅能为0-utf8/1-base64/2-hex";
			emit send(QJsonDocument(result).toJson());
			return;
		}
		}
		result["code"] = 0;
		result["msg"] = "success";
		emit send(QJsonDocument(result).toJson());
		return;
	}
	void get_data_size(const QString& jsonstr)
	{
		QJsonDocument doc = QJsonDocument::fromJson(jsonstr.toUtf8());
		QJsonObject json = doc.object();
		QJsonObject result;
		dog_data::Data data;
		std::string input = json["input"].toString().toStdString();
		if (json["inputType"].isNull() || json["inputType"].isUndefined() || !isInt(json["inputType"]))
		{
			result["code"] = 1;
			result["msg"] = "请选择输入类型";
			emit send(QJsonDocument(result).toJson());
			return;
		}
		uint64_t input_type = toInt(json["inputType"]);
		data = dog_data::Data(input, input_type);
		result["code"] = 0;
		result["msg"] = "success";
		QJsonValue size = data.size() < 0x20000000000000 ? QJsonValue(data.size() * 1.0) : QJsonValue("overflow");
		result["size"] = size;
		result["id"] = json["id"];
		emit size_back(QJsonDocument(result).toJson());
	}
signals:
	void send(const QString& json);
signals:
	void size_back(const QString& json);

};
class HashBridge : public QObject
{
	Q_OBJECT
public:
	explicit HashBridge(QObject* parent = nullptr) : QObject(parent) {}

public slots:
	void work(const QString& jsonStr)
	{
		QJsonDocument doc = QJsonDocument::fromJson(jsonStr.toUtf8());
		QJsonObject params = doc.object();
		QJsonObject result;
		dog_data::Data data;
		QString path;
		/*
		if (params["input"].toString().isEmpty())
		{
			result["code"] = 1;
			result["msg"] = "请输入数据";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		*/
		std::string input = params["input"].toString().toStdString();
		if (params["inputType"].isNull() || params["inputType"].isUndefined() || !isInt(params["inputType"]))
		{
			result["code"] = 1;
			result["msg"] = "请选择输入类型";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		int inputType = toInt(params["inputType"]);
		if (inputType != 3)
		{
			data = dog_data::Data(input, inputType);
		}

		if (params["type"].isNull() || params["type"].isUndefined() || !params["type"].isString())
		{
			result["code"] = 1;
			result["msg"] = "请选择散列类型";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		std::unique_ptr<dog_hash::HashConfig> hash_config = nullptr;
		for (auto& single_config : dog_hash::list)
		{
			if (single_config.name == params["type"].toString().toStdString())
			{
				hash_config = std::make_unique<dog_hash::HashConfig>(single_config);
				break;
			}
		}
		if (!hash_config)
		{
			result["code"] = 1;
			result["msg"] = "散列类型错误,不支持的散列类型";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		if (params["effective"].isNull() || params["effective"].isUndefined() || !params["effective"].isDouble())
		{
			result["code"] = 1;
			result["msg"] = "请输入有效输出数";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		else
		{
			QString effectiveStr = params["effective"].toString();
			double effective_double = effectiveStr.toDouble();
			if (effective_double != (uint64_t)effective_double)
			{
				result["code"] = 1;
				result["msg"] = "有效输出类型错误";
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			int effective = params["effective"].toInt();
			if (!dog_number::region::is_fall(hash_config->region, effective))
			{
				result["code"] = 1;
				result["msg"] = "有效输出错误,不支持的散列类型和有效输出组合";
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
		}

		if (inputType == 3)
		{
			if (input.empty())
			{
				result["code"] = 1;
				result["msg"] = "请输入文件路径";
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			path = QString::fromStdString(input);
			std::unordered_map<std::string, std::any> output_params;
			if (params["outputType"].isNull() || params["outputType"].isUndefined() || !isInt(params["outputType"]))
			{
				result["code"] = 1;
				result["msg"] = "请选择输出类型";
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			output_params["output_type"] = toInt(params["outputType"]);
			switch (std::any_cast<uint64_t>(output_params["output_type"]))
			{
			case 0:
			{
				break;
			}
			case 1:
			{
				if (params["replace0"].isNull() || params["replace0"].isUndefined()
					|| params["replace1"].isNull() || params["replace1"].isUndefined()
					|| params["replace2"].isNull() || params["replace2"].isUndefined())
				{
					result["code"] = 1;
					result["msg"] = "请输入替换字符";
					emit send_result(QJsonDocument(result).toJson());
					return;
				}
				else if (params["replace0"].toString() == params["replace1"].toString()
					|| params["replace0"].toString() == params["replace2"].toString()
					|| params["replace1"].toString() == params["replace2"].toString())
				{
					result["code"] = 1;
					result["msg"] = "替换字符不能相同";
					emit send_result(QJsonDocument(result).toJson());
					return;
				}
				output_params["replace0"] = params["replace0"].toString().toStdString()[0];
				output_params["replace1"] = params["replace1"].toString().toStdString()[0];
				output_params["replace2"] = params["replace2"].toString().toStdString()[0];
				break;
			}
			case 2:
			{
				if (params["upper"].isNull() || params["upper"].isUndefined())
				{
					result["code"] = 1;
					result["msg"] = "请指定大小写";
					emit send_result(QJsonDocument(result).toJson());
					return;
				}
				else if (!params["upper"].isBool())
				{
					result["code"] = 1;
					result["msg"] = "请正确指定大小写";
					emit send_result(QJsonDocument(result).toJson());
					return;
				}
				output_params["upper"] = params["upper"].toBool();
				break;
			}
			default:
			{
				result["code"] = 1;
				result["msg"] = "输出类型错误,仅能为0-utf8/1-base64/2-hex";
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			}
			dog_hash::HashCrypher hash_crypher(params["type"].toString().toStdString(), params["effective"].toInt());
			uint64_t id = task_pool->add_hash(path.toStdString(), hash_crypher, output_params);
			result["code"] = 0;
			result["file"] = true;
			result["msg"] = QString::fromStdString("任务已添加至队列,任务编号" + std::to_string(id));
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		else
		{
			try
			{
				dog_hash::HashCrypher hash_crypher(params["type"].toString().toStdString(), params["effective"].toInt());
				work::Timer t;
				t.start();
				data = hash_crypher.getDataHash(data);
				t.end();
				result["time"] = t.get_time();
			}
			catch (std::exception& e)
			{
				result["code"] = 1;
				result["msg"] = QString::fromStdString(e.what());
			}
		}
		if (params["outputType"].isNull() || params["outputType"].isUndefined() || !isInt(params["outputType"]))
		{
			result["code"] = 1;
			result["msg"] = "请选择输出类型";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		uint64_t output_type = toInt(params["outputType"]);
		switch (output_type)
		{
		case 0:
		{
			result["res"] = QString::fromStdString(data.getUTF8String());
			break;
		}
		case 1:
		{
			if (params["replace0"].isNull() || params["replace0"].isUndefined()
				|| params["replace1"].isNull() || params["replace1"].isUndefined()
				|| params["replace2"].isNull() || params["replace2"].isUndefined())
			{
				result["code"] = 1;
				result["msg"] = "请输入替换字符";
			}
			else if (params["replace0"].toString() == params["replace1"].toString()
				|| params["replace0"].toString() == params["replace2"].toString()
				|| params["replace1"].toString() == params["replace2"].toString())
			{
				result["code"] = 1;
				result["msg"] = "替换字符不能相同";
			}
			char replace0 = params["replace0"].toString().toStdString()[0];
			char replace1 = params["replace1"].toString().toStdString()[0];
			char replace2 = params["replace2"].toString().toStdString()[0];
			result["res"] = QString::fromStdString(data.getBase64String(replace0, replace1, replace2));
			break;
		}
		case 2:
		{
			if (params["upper"].isNull() || params["upper"].isUndefined())
			{
				result["code"] = 1;
				result["msg"] = "请指定大小写";
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			else if (!params["upper"].isBool())
			{
				result["code"] = 1;
				result["msg"] = "请正确指定大小写";
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			bool upper = params["upper"].toBool();
			result["res"] = QString::fromStdString(data.getHexString(upper));
			break;
		}
		default:
		{
			result["code"] = 1;
			result["msg"] = "输出类型错误,仅能为0-utf8/1-base64/2-hex";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		}
		result["code"] = 0;
		result["msg"] = "success";
		emit send_result(QJsonDocument(result).toJson());
		return;
	}
public slots:
	void test(const QString& jsonStr)
	{
		QJsonDocument doc = QJsonDocument::fromJson(jsonStr.toUtf8());
		QJsonObject params = doc.object();
		//qDebug() << params;
		std::string type = params["type"].toString().toStdString();
		uint64_t effective = params["effective"].toInt();
		dog_hash::HashCrypher hash(type, effective);
		dog_data::Data data = "";
		work::Timer t;
		t.start();
		hash.getDataHash(data);
		t.end();
		QJsonObject result;
		result["time"] = t.get_time();
		emit send_speed(QJsonDocument(result).toJson());
	}

signals:
	void send_result(const QString& jsonStr);
signals:
	void send_speed(const QString& jsonStr);
};
class EncryptionBridge : public QObject
{
	Q_OBJECT
public:
	explicit EncryptionBridge(QObject* parent = nullptr) : QObject(parent) {}

public slots:
	void work(const QString& jsonstr)
	{
		QJsonDocument doc = QJsonDocument::fromJson(jsonstr.toUtf8());
		QJsonObject params = doc.object();
		QJsonObject result;
		/*
{
	"head":{
		"withCheck":true,
		"withConfig":true,
		"withIV":true
	},
	"config":{
		"type":"AES",
		"blockSize":16,
		"keySize":16,

		"isPadding":true,
		"padding":"PKCS7",
		"mode":"ECB",
		"shift":15
	},
	"input":{
		"input":"11",
		"inputType":0,
		"outputType":"2",
		"upper":true
	}
}
		*/

		QJsonObject config_json = params["config"].toObject();
		std::string algorithm = "";
		if (config_json["type"].isNull() || config_json["type"].isUndefined() || !config_json["type"].isString())
		{
			result["code"] = 1;
			result["msg"] = "请正确选择加密类型";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		algorithm = config_json["type"].toString().toStdString();

		uint64_t block_size = 0;
		if (config_json["blockSize"].isNull() || config_json["blockSize"].isUndefined() || !isInt(config_json["blockSize"]))
		{
			result["code"] = 1;
			result["msg"] = "请正确选择加密分块长度";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		block_size = toInt(config_json["blockSize"]);

		uint64_t key_size = 0;
		if (config_json["keySize"].isNull() || config_json["keySize"].isUndefined() || !isInt(config_json["keySize"]))
		{
			result["code"] = 1;
			result["msg"] = "请正确选择加密密钥长度";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		key_size = toInt(config_json["keySize"]);

		bool using_padding = false;
		if (config_json["isPadding"].isNull() || config_json["isPadding"].isUndefined() || !config_json["isPadding"].isBool())
		{
			result["code"] = 1;
			result["msg"] = "请正确选择是否使用填充";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		using_padding = config_json["isPadding"].toBool();

		std::string padding = "";
		if (config_json["padding"].isNull() || config_json["padding"].isUndefined() || !config_json["padding"].isString())
		{
			result["code"] = 1;
			result["msg"] = "请正确选择填充类型";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		padding = config_json["padding"].toString().toStdString();

		std::string mode = "";
		if (config_json["mode"].isNull() || config_json["mode"].isUndefined() || !config_json["mode"].isString())
		{
			result["code"] = 1;
			result["msg"] = "请正确选择加密模式";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		mode = config_json["mode"].toString().toStdString();

		uint64_t shift = 0;
		if (config_json["shift"].isNull() || config_json["shift"].isUndefined() || !isInt(config_json["shift"]))
		{
			result["code"] = 1;
			result["msg"] = "请正确选择偏移长度";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		shift = toInt(config_json["shift"]);

		dog_data::Data iv_data;
		QJsonObject iv_json = params["iv"].toObject();
		//qDebug() << iv_json;
		if (iv_json["auto"].isBool())
		{
			iv_data = dog_cryption::utils::randiv(block_size);
			result["iv"] = QString::fromStdString(iv_data.getHexString());
		}
		else
		{
			if (iv_json["inputType"].isNull() || iv_json["inputType"].isUndefined() || !isInt(iv_json["inputType"]))
			{
				result["code"] = 1;
				result["msg"] = "iv请正确选择输入类型";
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			if (iv_json["input"].isNull() || iv_json["input"].isUndefined() || !iv_json["input"].isString())
			{
				result["code"] = 1;
				result["msg"] = "请输入iv";
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			iv_data = dog_data::Data(iv_json["input"].toString().toStdString(), toInt(iv_json["inputType"]));
		}

		QJsonObject key_json = params["key"].toObject();
		if (key_json["inputType"].isNull() || key_json["inputType"].isUndefined() || !isInt(key_json["inputType"]))
		{
            result["code"] = 1;
			result["msg"] = "key请正确选择输入类型";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		if (key_json["input"].isNull() || key_json["input"].isUndefined() || !key_json["input"].isString())
		{
			result["code"] = 1;
			result["msg"] = "请输入key";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		dog_data::Data key_data(key_json["input"].toString().toStdString(), toInt(key_json["inputType"]));

		QJsonObject head_json = params["head"].toObject();
		bool with_check = false;
		if (head_json["withCheck"].isNull() || head_json["withCheck"].isUndefined() || !head_json["withCheck"].isBool())
		{
			result["code"] = 1;
			result["msg"] = "请正确选择是否启用密钥校验";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		with_check = head_json["withCheck"].toBool();
		bool with_iv = false;
		if (head_json["withIV"].isNull() || head_json["withIV"].isUndefined() || !head_json["withIV"].isBool())
		{
			result["code"] = 1;
			result["msg"] = "请正确选择是否启用iv";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		with_iv = head_json["withIV"].toBool();
		bool with_config = false;
		if (head_json["withConfig"].isNull() || head_json["withConfig"].isUndefined() || !head_json["withConfig"].isBool())
		{
			result["code"] = 1;
			result["msg"] = "请正确选择是否启用配置";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		with_config = head_json["withConfig"].toBool();

		QJsonObject input_json = params["input"].toObject();
		if (input_json["inputType"].isNull() || input_json["inputType"].isUndefined() || !isInt(input_json["inputType"]))
		{
			result["code"] = 1;
			result["msg"] = "请正确选择输入类型";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		if (input_json["input"].isNull() || input_json["input"].isUndefined() || !input_json["input"].isString())
		{
			result["code"] = 1;
			result["msg"] = "请输入内容";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		uint64_t input_type = toInt(input_json["inputType"]);
		dog_data::Data input_data;
		if (input_type != 3)
		{
			dog_data::Data output_data;
			try
			{
				dog_cryption::CryptionConfig cryption_config(algorithm, block_size, key_size, using_padding, padding, mode, true, shift);
				dog_cryption::Cryptor cryptor(cryption_config);
				cryptor.set_key(key_data);
				input_data = dog_data::Data(input_json["input"].toString().toStdString(), input_type);
				work::Timer t;
				t.start();
				output_data = cryptor.encrypt(input_data, with_config, with_iv, iv_data, with_check);
				t.end();
				result["time"] = t.get_time();
			}
			catch (std::exception& e)
			{
				result["code"] = 1;
				result["msg"] = "内部错误,请保留日志并联系开发人员" + QString::fromStdString(e.what());
				emit send_result(QJsonDocument(result).toJson());
				return;
			}

			uint64_t output_type = 0;
			if (input_json["outputType"].isNull() || input_json["outputType"].isUndefined() || !isInt(input_json["outputType"]))
			{
				result["code"] = 1;
				result["msg"] = "请正确选择输出类型";
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			output_type = toInt(input_json["outputType"]);

			switch (output_type)
			{
			case 0:
			{
				result["res"] = QString::fromStdString(output_data.getUTF8String());
				break;
			}
			case 1:
			{
				if (input_json["replace0"].isNull() || input_json["replace0"].isUndefined()
					|| input_json["replace1"].isNull() || input_json["replace1"].isUndefined()
					|| input_json["replace2"].isNull() || input_json["replace2"].isUndefined())
				{
					result["code"] = 1;
					result["msg"] = "请输入替换字符";
					emit send_result(QJsonDocument(result).toJson());
					return;
				}
				else if (input_json["replace0"].toString() == input_json["replace1"].toString()
					|| input_json["replace0"].toString() == input_json["replace2"].toString()
					|| input_json["replace1"].toString() == input_json["replace2"].toString())
				{
					result["code"] = 1;
					result["msg"] = "替换字符不能相同";
					emit send_result(QJsonDocument(result).toJson());
					return;
				}
				char replace0 = input_json["replace0"].toString().toStdString()[0];
				char replace1 = input_json["replace1"].toString().toStdString()[0];
				char replace2 = input_json["replace2"].toString().toStdString()[0];
				result["res"] = QString::fromStdString(output_data.getBase64String(replace0, replace1, replace2));
				break;
			}
			case 2:
			{
				if (input_json["upper"].isNull() || input_json["upper"].isUndefined())
				{
					result["code"] = 1;
					result["msg"] = "请指定大小写";
					emit send_result(QJsonDocument(result).toJson());
					return;
				}
				else if (!input_json["upper"].isBool())
				{
					result["code"] = 1;
					result["msg"] = "请正确指定大小写";
					emit send_result(QJsonDocument(result).toJson());
					return;
				}
				bool upper = input_json["upper"].toBool();
				result["res"] = QString::fromStdString(output_data.getHexString(upper));
				break;
			}
			default:
			{
				result["code"] = 1;
				result["msg"] = "输出类型错误,仅能为0-utf8/1-base64/2-hex";
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			};
			result["code"] = 0;
			result["msg"] = "加密成功";
			emit send_result(QJsonDocument(result).toJson());
		}
		else
		{
			std::string input_path = input_json["input"].toString().toStdString();
			std::string output_path = input_json["output"].toString().toStdString();
			std::filesystem::path temp_input_path = std::filesystem::path(input_path);
			if (!std::filesystem::exists(temp_input_path))
			{
				result["code"] = 1;
				result["msg"] = "文件不存在";
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			if (std::filesystem::file_size(temp_input_path) == 0)
			{
				result["code"] = 1;
				result["msg"] = "文件为空";
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			std::unique_ptr<dog_cryption::Cryptor> cryptor;
			try
			{
				dog_cryption::CryptionConfig cryption_config(algorithm, block_size, key_size, using_padding, padding, mode, true, shift);
				cryptor = std::make_unique<dog_cryption::Cryptor>(cryption_config);
				cryptor->set_key(key_data);
			}
			catch (std::exception& e)
			{
				result["code"] = 1;
				result["msg"] = "内部错误,请保留日志并联系开发人员" + QString::fromStdString(e.what());
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			uint64_t id = task_pool->add_encrypt(input_path, output_path, *cryptor,
				iv_data, with_config, with_iv, with_check);
			result["code"] = 0;
			result["file"] = true;
			result["msg"] = QString::fromStdString("任务已添加至队列,任务编号" + std::to_string(id));
			emit send_result(QJsonDocument(result).toJson());
			return;
		}

	};
public slots:
	void test(const QString& jsonstr)
	{
		QJsonDocument doc = QJsonDocument::fromJson(jsonstr.toUtf8());
		QJsonObject params = doc.object();
		QJsonObject result;

		std::unique_ptr<dog_cryption::AlgorithmConfig> algorithm_config = nullptr;
		if (params["type"].isNull() || params["type"].isUndefined() || params["type"].toString().isEmpty())
		{
			result["code"] = 1;
			result["msg"] = "请正确选择加密类型";
			emit send_speed(QJsonDocument(result).toJson());
			return;
		}
		for (auto& item : dog_cryption::Algorithm_list)
		{
			if (item.name == params["type"].toString().toStdString())
			{
				algorithm_config = std::make_unique<dog_cryption::AlgorithmConfig>(item);
                break;
			}
		}
		if (!algorithm_config)
		{
			result["code"] = 1;
			result["msg"] = "请选择正确的加密类型";
			emit send_speed(QJsonDocument(result).toJson());
			return;
		}

		if (params["keySize"].isNull() || params["keySize"].isUndefined() || !isInt(params["keySize"]))
		{
			result["code"] = 1;
			result["msg"] = "请正确选择加密密钥长度";
			emit send_speed(QJsonDocument(result).toJson());
			return;
		}
		uint64_t key_size = params["keySize"].toDouble();
		if (!dog_number::region::is_fall(algorithm_config->key_size_region, key_size))
		{
			result["code"] = 1;
			result["msg"] = "请选择正确的加密密钥长度";
			emit send_speed(QJsonDocument(result).toJson());
			return;
		}

		if (params["blockSize"].isNull() || params["blockSize"].isUndefined() || !isInt(params["blockSize"]))
		{
			result["code"] = 1;
			result["msg"] = "请正确选择加密分块长度";
			emit send_speed(QJsonDocument(result).toJson());
			return;
		}
		uint64_t block_size = params["blockSize"].toDouble();
		if (!dog_number::region::is_fall(algorithm_config->block_size_region, block_size))
		{
			result["code"] = 1;
			result["msg"] = "请选择正确的加密分块长度";
			emit send_speed(QJsonDocument(result).toJson());
			return;
		}

		dog_cryption::Cryptor cryptor(algorithm_config->name, block_size, key_size, true, "PKCS7", "ECB", false, 0);
		dog_data::Data block = dog_cryption::utils::randiv(block_size);
		dog_data::Data key = dog_cryption::utils::randiv(key_size);
		cryptor.set_key(key);
		work::Timer t;
		t.start();
		cryptor.get_block_encryption()(block, block_size, cryptor.get_available_key(), key_size);
		t.end();
		result["code"] = 0;
		result["time"] = t.get_time();
		emit send_speed(QJsonDocument(result).toJson());
	};

signals:
	void send_result(const QString& jsonStr);
signals:
	void send_speed(const QString& jsonStr);
};
class DecryptionBridge : public QObject
{
	Q_OBJECT
public:
	explicit DecryptionBridge(QObject* parent = nullptr) : QObject(parent) {}
public slots:
	void work(const QString& jsonstr)
	{
		QJsonDocument doc = QJsonDocument::fromJson(jsonstr.toUtf8());
		QJsonObject params = doc.object();
		QJsonObject result;
		/*
{
    "config": {
        "blockSize": 16,
        "isPadding": true,
        "keySize": 16,
        "mode": "ECB",
        "padding": "PKCS7",
        "shift": 1,
        "type": "AES"
    },
    "head": {
        "withCheck": true,
        "withConfig": true,
        "withIV": true
    },
    "input": {
        "input": "0123456789ABCDEF",
        "inputType": 2,
        "outputType": 0
    },
    "iv": {
        "input": "0123456789ABCDEF",
        "inputType": 0
    },
    "key": {
        "input": "0123456789ABCDEF",
        "inputType": 0
    }
}
		*/
		QJsonObject config_json = params["config"].toObject();
		std::string algorithm = "";
		if (config_json["type"].isNull() || config_json["type"].isUndefined() || !config_json["type"].isString())
		{
			result["code"] = 1;
			result["msg"] = "请正确选择加密类型";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		algorithm = config_json["type"].toString().toStdString();

		uint64_t block_size = 0;
		if (config_json["blockSize"].isNull() || config_json["blockSize"].isUndefined() || !isInt(config_json["blockSize"]))
		{
			result["code"] = 1;
			result["msg"] = "请正确选择加密分块长度";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		block_size = toInt(config_json["blockSize"]);

		uint64_t key_size = 0;
		if (config_json["keySize"].isNull() || config_json["keySize"].isUndefined() || !isInt(config_json["keySize"]))
		{
			result["code"] = 1;
			result["msg"] = "请正确选择加密密钥长度";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		key_size = toInt(config_json["keySize"]);

		bool using_padding = false;
		if (config_json["isPadding"].isNull() || config_json["isPadding"].isUndefined() || !config_json["isPadding"].isBool())
		{
			result["code"] = 1;
			result["msg"] = "请正确选择是否使用填充";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		using_padding = config_json["isPadding"].toBool();

		std::string padding = "";
		if (config_json["padding"].isNull() || config_json["padding"].isUndefined() || !config_json["padding"].isString())
		{
			result["code"] = 1;
			result["msg"] = "请正确选择填充类型";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		padding = config_json["padding"].toString().toStdString();

		std::string mode = "";
		if (config_json["mode"].isNull() || config_json["mode"].isUndefined() || !config_json["mode"].isString())
		{
			result["code"] = 1;
			result["msg"] = "请正确选择加密模式";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		mode = config_json["mode"].toString().toStdString();

		uint64_t shift = 0;
		if (config_json["shift"].isNull() || config_json["shift"].isUndefined() || !isInt(config_json["shift"]))
		{
			result["code"] = 1;
			result["msg"] = "请正确选择偏移长度";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		shift = toInt(config_json["shift"]);

		QJsonObject iv_json = params["iv"].toObject();
		if (iv_json["inputType"].isNull() || iv_json["inputType"].isUndefined() || !isInt(iv_json["inputType"]))
		{
			result["code"] = 1;
			result["msg"] = "iv请正确选择输入类型";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		if (iv_json["input"].isNull() || iv_json["input"].isUndefined() || !iv_json["input"].isString())
		{
			result["code"] = 1;
			result["msg"] = "请输入iv";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		dog_data::Data iv_data = dog_data::Data(iv_json["input"].toString().toStdString(), toInt(iv_json["inputType"]));

		QJsonObject key_json = params["key"].toObject();
		if (key_json["inputType"].isNull() || key_json["inputType"].isUndefined() || !isInt(key_json["inputType"]))
		{
			result["code"] = 1;
			result["msg"] = "key请正确选择输入类型";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		if (key_json["input"].isNull() || key_json["input"].isUndefined() || !key_json["input"].isString())
		{
			result["code"] = 1;
			result["msg"] = "请输入key";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		dog_data::Data key_data(key_json["input"].toString().toStdString(), toInt(key_json["inputType"]));

		QJsonObject head_json = params["head"].toObject();
		bool with_check = false;
		if (head_json["withCheck"].isNull() || head_json["withCheck"].isUndefined() || !head_json["withCheck"].isBool())
		{
			result["code"] = 1;
			result["msg"] = "请正确选择是否启用密钥校验";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		with_check = head_json["withCheck"].toBool();
		bool with_iv = false;
		if (head_json["withIV"].isNull() || head_json["withIV"].isUndefined() || !head_json["withIV"].isBool())
		{
			result["code"] = 1;
			result["msg"] = "请正确选择是否启用iv";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		with_iv = head_json["withIV"].toBool();
		bool with_config = false;
		if (head_json["withConfig"].isNull() || head_json["withConfig"].isUndefined() || !head_json["withConfig"].isBool())
		{
			result["code"] = 1;
			result["msg"] = "请正确选择是否启用配置";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		with_config = head_json["withConfig"].toBool();

		if (!with_iv && iv_data.size() < block_size)
		{
			result["code"] = 1;
			result["msg"] = "iv长度不足,当前" + QString::number(iv_data.size()) + "位(B)" + "需要" + QString::number(block_size) + "位(B)";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}

		QJsonObject input_json = params["input"].toObject();
		if (input_json["inputType"].isNull() || input_json["inputType"].isUndefined() || !isInt(input_json["inputType"]))
		{
			result["code"] = 1;
			result["msg"] = "请正确选择输入类型";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		if (input_json["input"].isNull() || input_json["input"].isUndefined() || !input_json["input"].isString())
		{
			result["code"] = 1;
			result["msg"] = "请输入内容";
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
		uint64_t input_type = toInt(input_json["inputType"]);
		dog_data::Data input_data;
		QString input_path = "";
		if (input_type != 3)
		{
			dog_data::Data output_data;
			try
			{
				dog_cryption::CryptionConfig cryption_config(algorithm, block_size, key_size, using_padding, padding, mode, true, shift);
				dog_cryption::Cryptor cryptor(cryption_config);
				cryptor.set_key(key_data);
				input_data = dog_data::Data(input_json["input"].toString().toStdString(), input_type);
				work::Timer t;
				t.start();
				output_data = cryptor.decrypt(input_data, with_config, with_iv, iv_data, with_check);
				t.end();
				result["time"] = t.get_time();
			}
			catch (dog_cryption::WrongKeyException& e)
			{
				result["code"] = 1;
				result["msg"] = "密钥校验失败,请输入正确的密钥";
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			catch (dog_cryption::WrongConfigException& e)
			{
				result["code"] = 1;
				result["msg"] = "前导配置错误,请确保配置字节不被修改";
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			catch (std::exception& e)
			{
				result["code"] = 1;
				result["msg"] = "内部错误,请保留日志并联系开发人员" + QString::fromStdString(e.what());
				emit send_result(QJsonDocument(result).toJson());
				return;
			}

			uint64_t output_type = 0;
			if (input_json["outputType"].isNull() || input_json["outputType"].isUndefined() || !isInt(input_json["outputType"]))
			{
				result["code"] = 1;
				result["msg"] = "请正确选择输出类型";
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			output_type = toInt(input_json["outputType"]);

			switch (output_type)
			{
			case 0:
			{
				result["res"] = QString::fromStdString(output_data.getUTF8String());
				break;
			}
			case 1:
			{
				if (input_json["replace0"].isNull() || input_json["replace0"].isUndefined()
					|| input_json["replace1"].isNull() || input_json["replace1"].isUndefined()
					|| input_json["replace2"].isNull() || input_json["replace2"].isUndefined())
				{
					result["code"] = 1;
					result["msg"] = "请输入替换字符";
					emit send_result(QJsonDocument(result).toJson());
					return;
				}
				else if (input_json["replace0"].toString() == input_json["replace1"].toString()
					|| input_json["replace0"].toString() == input_json["replace2"].toString()
					|| input_json["replace1"].toString() == input_json["replace2"].toString())
				{
					result["code"] = 1;
					result["msg"] = "替换字符不能相同";
					emit send_result(QJsonDocument(result).toJson());
					return;
				}
				char replace0 = input_json["replace0"].toString().toStdString()[0];
				char replace1 = input_json["replace1"].toString().toStdString()[0];
				char replace2 = input_json["replace2"].toString().toStdString()[0];
				result["res"] = QString::fromStdString(output_data.getBase64String(replace0, replace1, replace2));
				break;
			}
			case 2:
			{
				if (input_json["upper"].isNull() || input_json["upper"].isUndefined())
				{
					result["code"] = 1;
					result["msg"] = "请指定大小写";
					emit send_result(QJsonDocument(result).toJson());
					return;
				}
				else if (!input_json["upper"].isBool())
				{
					result["code"] = 1;
					result["msg"] = "请正确指定大小写";
					emit send_result(QJsonDocument(result).toJson());
					return;
				}
				bool upper = input_json["upper"].toBool();
				result["res"] = QString::fromStdString(output_data.getHexString(upper));
				break;
			}
			default:
			{
				result["code"] = 1;
				result["msg"] = "输出类型错误,仅能为0-utf8/1-base64/2-hex";
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			};
			result["code"] = 0;
			result["msg"] = "解密成功";
			emit send_result(QJsonDocument(result).toJson());
		}
		else
		{
			std::string input_path = input_json["input"].toString().toStdString();
			std::string output_path = input_json["output"].toString().toStdString();
			std::filesystem::path temp_input_path = input_path;
			if (!std::filesystem::exists(temp_input_path))
			{
				result["code"] = 1;
				result["msg"] = "文件不存在";
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			if (std::filesystem::file_size(temp_input_path) == 0)
			{
				result["code"] = 1;
				result["msg"] = "文件为空";
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			std::unique_ptr<dog_cryption::Cryptor> cryptor;
			try
			{
				dog_cryption::CryptionConfig cryption_config(algorithm, block_size, key_size, using_padding, padding, mode, true, shift);
				cryptor = std::make_unique<dog_cryption::Cryptor>(cryption_config);
				cryptor->set_key(key_data);
			}
			catch (std::exception& e)
			{
				result["code"] = 1;
				result["msg"] = "内部错误,请保留日志并联系开发人员" + QString::fromStdString(e.what());
				emit send_result(QJsonDocument(result).toJson());
				return;
			}
			uint64_t id = task_pool->add_decrypt(input_path, output_path, *cryptor,
				iv_data, with_config, with_iv, with_check);
			result["code"] = 0;
			result["file"] = true;
			result["msg"] = QString::fromStdString("任务已添加至队列,任务编号" + std::to_string(id));
			emit send_result(QJsonDocument(result).toJson());
			return;
		}
	}
public slots:
	void test(const QString& jsonstr)
	{
		QJsonDocument doc = QJsonDocument::fromJson(jsonstr.toUtf8());
		QJsonObject params = doc.object();
		QJsonObject result;

		std::unique_ptr<dog_cryption::AlgorithmConfig> algorithm_config = nullptr;
		if (params["type"].isNull() || params["type"].isUndefined() || params["type"].toString().isEmpty())
		{
			result["code"] = 1;
			result["msg"] = "请正确选择加密类型";
			emit send_speed(QJsonDocument(result).toJson());
			return;
		}
		for (auto& item : dog_cryption::Algorithm_list)
		{
			if (item.name == params["type"].toString().toStdString())
			{
				algorithm_config = std::make_unique<dog_cryption::AlgorithmConfig>(item);
				break;
			}
		}
		if (!algorithm_config)
		{
			result["code"] = 1;
			result["msg"] = "请选择正确的加密类型";
			emit send_speed(QJsonDocument(result).toJson());
			return;
		}

		if (params["keySize"].isNull() || params["keySize"].isUndefined() || !isInt(params["keySize"]))
		{
			result["code"] = 1;
			result["msg"] = "请正确选择加密密钥长度";
			emit send_speed(QJsonDocument(result).toJson());
			return;
		}
		uint64_t key_size = params["keySize"].toDouble();
		if (!dog_number::region::is_fall(algorithm_config->key_size_region, key_size))
		{
			result["code"] = 1;
			result["msg"] = "请选择正确的加密密钥长度";
			emit send_speed(QJsonDocument(result).toJson());
			return;
		}

		if (params["blockSize"].isNull() || params["blockSize"].isUndefined() || !isInt(params["blockSize"]))
		{
			result["code"] = 1;
			result["msg"] = "请正确选择加密分块长度";
			emit send_speed(QJsonDocument(result).toJson());
			return;
		}
		uint64_t block_size = params["blockSize"].toDouble();
		if (!dog_number::region::is_fall(algorithm_config->block_size_region, block_size))
		{
			result["code"] = 1;
			result["msg"] = "请选择正确的加密分块长度";
			emit send_speed(QJsonDocument(result).toJson());
			return;
		}

		dog_cryption::Cryptor cryptor(algorithm_config->name, block_size, key_size, true, "PKCS7", "ECB", false, 0);
		dog_data::Data block = dog_cryption::utils::randiv(block_size);
		dog_data::Data key = dog_cryption::utils::randiv(key_size);
		cryptor.set_key(key);
		work::Timer t;
		t.start();
		cryptor.get_block_decryption()(block, block_size, cryptor.get_available_key(), key_size);
		t.end();
		result["code"] = 0;
		result["time"] = t.get_time();
		emit send_speed(QJsonDocument(result).toJson());
	}
signals:
	void send_result(const QString& jsonStr);
signals:
	void send_speed(const QString& jsonStr);
};

class TaskBridge : public QObject
{
	Q_OBJECT
public:
	explicit TaskBridge(QObject* parent = nullptr) : QObject(parent) {}

public slots:
	void get_all_running()
	{
		QJsonArray results;
		std::vector<std::unordered_map<std::string, std::any>> tasks = task_pool->get_all_running_task_info();
		for (auto& task : tasks)
		{
			QJsonObject row;
			for (auto& item : task)
			{
				QString key = QString::fromStdString(item.first);
				if (item.second.type() == typeid(uint64_t))
				{
					row[key] = QJsonValue((int32_t)std::any_cast<uint64_t>(item.second));
				}
				else if (item.second.type() == typeid(int))
				{
					row[key] = QJsonValue((int32_t)std::any_cast<int>(item.second));
				}
				else if (item.second.type() == typeid(std::string))
				{
					row[key] = QString::fromStdString(std::any_cast<std::string>(item.second));
				}
				else if (item.second.type() == typeid(double))
				{
					row[key] = QJsonValue(std::any_cast<double>(item.second));
				}
				else if (item.second.type() == typeid(bool))
				{
					row[key] = QJsonValue(std::any_cast<bool>(item.second));
				}
			}
			results.append(row);
		}
        emit send_all_running(QJsonDocument(results).toJson());
		return;
	}
public slots:
	void get_all_waitting()
	{
		QJsonArray results;
		std::vector<std::unordered_map<std::string, std::any>> tasks = task_pool->get_all_waitting_task_info();
		for (auto& task : tasks)
		{
			QJsonObject row;
			for (auto& item : task)
			{
				QString key = QString::fromStdString(item.first);
				if (item.second.type() == typeid(uint64_t))
				{
					row[key] = QJsonValue((int32_t)std::any_cast<uint64_t>(item.second));
				}
				else if (item.second.type() == typeid(int))
				{
					row[key] = QJsonValue((int32_t)std::any_cast<int>(item.second));
				}
				else if (item.second.type() == typeid(std::string))
				{
					row[key] = QString::fromStdString(std::any_cast<std::string>(item.second));
				}
				else if (item.second.type() == typeid(double))
				{
					row[key] = QJsonValue(std::any_cast<double>(item.second));
				}
				else if (item.second.type() == typeid(bool))
				{
					row[key] = QJsonValue(std::any_cast<bool>(item.second));
				}
			}
			results.append(row);
		}
		emit send_all_waitting(QJsonDocument(results).toJson());
		return;
	}
public slots:
	void pause_task(const QString& jsonStr)
	{
		QJsonDocument doc = QJsonDocument::fromJson(jsonStr.toUtf8());
		QJsonObject json = doc.object();
		if (json["id"].isNull() || json["id"].isUndefined() || !isInt(json["id"]))
		{
			return;
		}
		uint64_t id = toInt(json["id"]);
		task_pool->pause_task(id);
	}
public slots:
	void resume_task(const QString& jsonStr)
	{
		QJsonDocument doc = QJsonDocument::fromJson(jsonStr.toUtf8());
		QJsonObject json = doc.object();
		if (json["id"].isNull() || json["id"].isUndefined() || !isInt(json["id"]))
		{
			return;
		}
		uint64_t id = toInt(json["id"]);
		task_pool->resume_task(id);
	}
public slots:
	void stop_task(const QString& jsonStr)
	{
		QJsonDocument doc = QJsonDocument::fromJson(jsonStr.toUtf8());
		QJsonObject json = doc.object();
		if (json["id"].isNull() || json["id"].isUndefined() || !isInt(json["id"]))
		{
			return;
		}
		uint64_t id = toInt(json["id"]);
		task_pool->stop_task(id);
	}

signals:
	void send_all_running(const QString& jsonStr);
signals:
	void send_all_waitting(const QString& jsonStr);
};

class InfoWindow : public QMainWindow
{
	Q_OBJECT
private:
	QLabel* 文本 = nullptr;
public:
	InfoWindow(QWidget* parent = nullptr) : QMainWindow(parent)
	{
		setWindowTitle("正在启动...");
		resize(300, 200);
		QWidget* centralWidget = new QWidget(this);
		QVBoxLayout* layout = new QVBoxLayout(centralWidget);

		// 创建标签并设置文本
		文本 = new QLabel("正在校验文件完整性,这可能需要一点时间......", centralWidget);
		文本->setAlignment(Qt::AlignCenter);

		layout->addWidget(文本);

		// 设置中央部件
		setCentralWidget(centralWidget);
		if (auto screen = QGuiApplication::primaryScreen()) {
			QRect screenGeometry = screen->geometry();
			move(screenGeometry.center() - rect().center() - QPoint(0, 30));
		}
	};

	~InfoWindow()
	{
		this->close();
		delete 文本;
	}
	
	void changeText(const QString& text)
	{
		this->文本->setText(text);
	}
};

class CryptionWindow : public QMainWindow
{
	Q_OBJECT
	InfoWindow* infoWindow = new InfoWindow(this);

	QWebEngineView *view = new QWebEngineView(this);
	QWebEngineView *devTools = new QWebEngineView(this);

	CopyBridge* copyBridge = new CopyBridge(this);
	FileBridge* fileBridge = new FileBridge(this);

	HashListBridge* hashListBridge = new HashListBridge(this);

	PaddingListBridge* paddingListBridge = new PaddingListBridge(this);
	ModeListBridge* modeListBridge = new ModeListBridge(this);
	AlgorithmListBridge* algorithmListBridge = new AlgorithmListBridge(this);

	ExchangeBridge* exchangeBridge = new ExchangeBridge(this);
	HashBridge* hashBridge = new HashBridge(this);
	EncryptionBridge* encryptionBridge = new EncryptionBridge(this);
	DecryptionBridge* decryptionBridge = new DecryptionBridge(this);

	TaskBridge* taskBridge = new TaskBridge(this);
	
	bool is_effective_ = true;

public:
	CryptionWindow(QWidget* parent = nullptr) : QMainWindow(parent)
	{
		infoWindow->show();
		check();
		if (!is_effective_)
		{
			infoWindow->changeText("文件校验失败,请重新下载程序!");
			this->infoWindow->setVisible(false);
			delete this->infoWindow;
			return;
		}
		infoWindow->changeText("程序初始化");
		/*
		qDebug() << QCoreApplication::applicationDirPath() + "/page/home.html";
		*/
		this->setAcceptDrops(true);
		/*QUrl url = QUrl::fromLocalFile("E:/project/crypher_cpp/src/win/home.html");*/
		QUrl url = QUrl::fromLocalFile(QCoreApplication::applicationDirPath() + "/page/home.html");

		QWebChannel* channel = new QWebChannel(this);

		channel->registerObject("paddingListBridge", this->paddingListBridge);
		QObject::connect(
			paddingListBridge, &PaddingListBridge::send, [this](const QJsonArray& jsons) -> void
			{
				this->view->page()->runJavaScript(QString("receivePaddingConfig(%1)").arg(QJsonDocument(jsons).toJson()));
			}
		);

		channel->registerObject("modeListBridge", this->modeListBridge);
		QObject::connect(
			modeListBridge, &ModeListBridge::send, [this](const QJsonArray& jsons) -> void
			{
				this->view->page()->runJavaScript(QString("receiveModeConfig(%1)").arg(QJsonDocument(jsons).toJson()));
			}
		);

		channel->registerObject("algorithmListBridge", this->algorithmListBridge);
		QObject::connect(
			algorithmListBridge, &AlgorithmListBridge::send, [this](const QJsonArray& jsons) -> void
			{
				this->view->page()->runJavaScript(QString("receiveAlgorithmConfig(%1)").arg(QJsonDocument(jsons).toJson()));
			}
		);

		channel->registerObject("hashListBridge", this->hashListBridge);
		QObject::connect(
			hashListBridge, &HashListBridge::send, [this](const QJsonArray& jsons) -> void
			{
				this->view->page()->runJavaScript(QString("receiveHashConfig(%1)").arg(QJsonDocument(jsons).toJson()));
			}
		);

		channel->registerObject("fileBridge", this->fileBridge);
		QObject::connect(
			fileBridge, &FileBridge::send, [this](const QString& jsonstr) -> void
			{
				this->view->page()->runJavaScript(QString("updateFile(%1)").arg(jsonstr));
			}
		);
		QObject::connect(
			fileBridge, &FileBridge::send_save, [this](const QString& jsonstr) -> void
			{
				this->view->page()->runJavaScript(QString("updateDir(%1)").arg(jsonstr));
			}
		);
		QObject::connect(
			fileBridge, &FileBridge::send_remove, [this](const QString& jsonStr) -> void
			{
				this->view->page()->runJavaScript(QString("deleteFile(%1)").arg(jsonStr));
			}
		);

		channel->registerObject("copyBridge", this->copyBridge);
		QObject::connect(
			copyBridge, &CopyBridge::send, [this](const QString& jsonStr) -> void
			{
				this->view->page()->runJavaScript(QString("qtCopyBack(%1)").arg(jsonStr));
			}
		);

		channel->registerObject("exchangeBridge", this->exchangeBridge);
		QObject::connect(
			exchangeBridge, &ExchangeBridge::send, [this](const QString& jsonStr) -> void
			{
				this->view->page()->runJavaScript(QString("qtExchangeBack(%1)").arg(jsonStr));
			}
		);
		QObject::connect(
			exchangeBridge, &ExchangeBridge::size_back, [this](const QString& jsonStr) -> void
			{
				this->view->page()->runJavaScript(QString("sizeBack(%1)").arg(jsonStr));
			}
		);

		channel->registerObject("hashBridge", this->hashBridge);
		QObject::connect(
			hashBridge, &HashBridge::send_speed, [this](const QString& jsonStr) -> void
			{
				this->view->page()->runJavaScript(QString("updateHashSpeed(%1)").arg(jsonStr));
			}
		);
		QObject::connect(
			hashBridge, &HashBridge::send_result, [this](const QString& jsonStr) -> void
			{
				this->view->page()->runJavaScript(QString("updateHashResult(%1)").arg(jsonStr));
			}
		);

		channel->registerObject("encryptionBridge", this->encryptionBridge);
		QObject::connect(
			encryptionBridge, &EncryptionBridge::send_speed, [this](const QString& jsonStr) -> void
			{
				this->view->page()->runJavaScript(QString("updateEncryptionSpeed(%1)").arg(jsonStr));
			}
		);
		QObject::connect(
			encryptionBridge, &EncryptionBridge::send_result, [this](const QString& jsonStr) -> void
			{
				this->view->page()->runJavaScript(QString("updateEncryptionResult(%1)").arg(jsonStr));
			}
		);

		channel->registerObject("decryptionBridge", this->decryptionBridge);
		QObject::connect(
			decryptionBridge, &DecryptionBridge::send_speed, [this](const QString& jsonStr) -> void
			{
				this->view->page()->runJavaScript(QString("updateDecryptionSpeed(%1)").arg(jsonStr));
			}
		);
		QObject::connect(
			decryptionBridge, &DecryptionBridge::send_result, [this](const QString& jsonStr) -> void
			{
				this->view->page()->runJavaScript(QString("updateDecryptionResult(%1)").arg(jsonStr));
			}
		);

		channel->registerObject("taskBridge", this->taskBridge);
		QObject::connect(
			taskBridge, &TaskBridge::send_all_running, [this](const QString& jsonStr) -> void
			{
				this->view->page()->runJavaScript(QString("updateRunning(%1)").arg(jsonStr));
			}
		);
		QObject::connect(
			taskBridge, &TaskBridge::send_all_waitting, [this](const QString& jsonStr) -> void
			{
				this->view->page()->runJavaScript(QString("updateWaitting(%1)").arg(jsonStr));
			}
		);

		view->setAcceptDrops(false);
		view->page()->setWebChannel(channel);
		view->page()->settings()->setAttribute(QWebEngineSettings::LocalStorageEnabled, true);
		devTools->resize(1200, 400);
        setCentralWidget(view);
		devTools->setVisible(false);
		view->load(url);
		view->page()->setDevToolsPage(devTools->page());
		view->resize(1200, 750);
		this->resize(1200, 750);
		view->setContextMenuPolicy(Qt::NoContextMenu);
		if (auto screen = QGuiApplication::primaryScreen()) {
			QRect screenGeometry = screen->geometry();
			move(screenGeometry.center() - rect().center() - QPoint(0, 30));
		}
		this->infoWindow->setVisible(false);
		delete this->infoWindow;
		
	}
	bool get_is_effective() const
	{
		return this->is_effective_;
	}
protected:
	void keyPressEvent(QKeyEvent* event) override 
	{
		//if ((event->modifiers() & (Qt::ControlModifier | Qt::ShiftModifier)) == (Qt::ControlModifier | Qt::ShiftModifier)
		//	&& event->key() == Qt::Key_I)
		//{
		//	devTools->show();
		//	devTools->move(0, 350);
		//}
		//else if (event->key() == Qt::Key_Delete)
		//{
		//	devTools->hide();
		//}
	}

	void closeEvent(QCloseEvent* event) override
	{
        QMainWindow::closeEvent(event);
		event->accept();
		deleteLater();
	}

	void dragEnterEvent(QDragEnterEvent* event) override {
		if (event->mimeData()->hasUrls()) {
			event->acceptProposedAction();
		}
	}

	void dropEvent(QDropEvent* event) override {
		const QMimeData* mimeData = event->mimeData();
		if (mimeData->hasUrls()) {
			QList<QUrl> urlList = mimeData->urls();
			for (const QUrl& url : urlList) {
				QString filePath = url.toLocalFile();
				//qDebug() << "拖拽的文件路径:" << filePath;
				this->view->page()->runJavaScript(QString("dropUpdateFile(\"%1\")").arg(filePath));
			}
		}
	}

	void check()
	{
		std::string now_path = QCoreApplication::applicationDirPath().toStdString() + "/page";
		std::vector<std::pair<std::string, std::string>> files_hash = {
			{"/home.html",                    "4B23CBB0457FF5942651909242D115930C587024FE3D28A6438A3AD160CC0DBC"},
			{"/home.css",                     "7FC9FE472A1862EEF198929EFE1258A9B8942EF7F0D243C115F60848113F041E"},
			{"/home.js",                      "92D3D16BB4B969D369491C95FE6EA9BB11E10A505511B677B72A3619433CDC9F"},
			{"/qwebchannel.js",               "11A729305F8DECA8F8F6C8B3A2218F613AAA47816B67B6141498FAB3752E15A3"},
			{"/resource/ArrowsRightLeft.svg", "DBDBD131CD8721ED7B8318EAECA69ED8BB262D4642B093DB423D2BAC3D47DE16"},
			{"/resource/cplusplus.svg",       "7FF8253551235E3A6B002A7C2BD6E3190D85113A64FCB40F2254473CAEB025D4"},
			{"/resource/css3.svg",            "36B7D94B657D571D3F94042ACBF6A4C86A5301A222F83F4B4583AD2ACF6E297D"},
			{"/resource/Hashtag.svg",         "D60624778FBF20721A47253EC9F043AC8AD90A0464A21ABFDAB8025ECA816F55"},
			{"/resource/hashTag0.svg",        "1FCA1C41FCA3363D08DDA2AA07E1E1CA4763315D607A44F62AC9FFD6D27C0C98"},
			{"/resource/html5.svg",           "34826E5B3315DAADF4FA15F723A3C1D5BA4A89277BFD94E22AC4D7D3D54338C5"},
			{"/resource/javascript.svg",      "0656FF65FC8EEACDA5C78D7F9FFE91EC1EB919DB64F56E0B7DCD460AF4BBD36C"},
			{"/resource/LockClosed.svg",      "49FEB6E288C0425EBB72A4E279DCF8B6613C9B30050408D1A7E6FA6D9AF7B9CC"},
			{"/resource/LockOpen.svg",        "A922A5A31702C9E711EFFBDF3281E3DBC077771938D983D3A32728EAAA6AD6B2"},
			{"/resource/msyh.ttc",            "D79C55E68B1131EEA0CC1C47BE4F572D964F28C682E143DB2AD09C1E4CB07A3F"},
			{"/resource/msyhbd.ttc",          "4508821B3DFFE01F0EF5E5326A3E60DF705A44633858811F67B6982DCE3F6EE6"},
			{"/resource/msyhl.ttc",           "7E9BDF90BB5D3FE1B5975FC8AE31944B8FA674122261F92C28D4EC0B9C482FA1"},
			{"/resource/NotoColorEmoji.ttf",  "3ED77810C203E1A67735DC19D395F32C23F2D7C0C3696690F4F78E15E57AB816"},
			{"/resource/NotoSansSC-VF.ttf",   "763146584CF0710223441356B4395E279021B0806C196614377A7A0174AE074A"},
			{"/resource/qt.svg",              "03B72B7D8C57FCEDFAAAC7052E8B2B0ABFB65FE11910A8A14B1D7FBBD69E1332"},
			{"/resource/task.svg",            "25E15697A20BFFF64440850AAB2B7FDA6FA29B2A895C1421418C9E9187A67786"},
			{"/resource/联想小新黑体_常规.ttf", "077F13D68FD1832564E2A1B0678F0D36EC339D068F3608C6EF95A6BC8D74835E"},
		};
		dog_hash::HashCrypher crypher("SHA2", 32);
		for (auto& file : files_hash)
		{
			std::string file_path = now_path + file.first;
			std::ifstream file_stream(file_path, std::ios::binary);
			if (!file_stream.is_open())
			{
				this->is_effective_ = false;
				return;
			}
			std::string hash_str = dog_hash::HashCrypher::streamHash(crypher, file_stream).getHexString();
			crypher.init();
			if (hash_str != file.second)
			{
				this->is_effective_ = false;
				return;
			}
		}
	}

	
};

int main(int argc, char* argv[])
{
	QApplication app(argc, argv);

	CryptionWindow* window = new CryptionWindow();
	task_pool = new work::TaskPool(8);
	if (window->get_is_effective())
	{
		window->show();
	}
	else
	{
		QMessageBox::information(nullptr, "提示", "程序文件被修改,请重新下载安装");
		app.exit(0);
		return 0;
	}

	return app.exec();
}

#include "qtwin.moc"
