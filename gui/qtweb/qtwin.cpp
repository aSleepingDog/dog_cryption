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

#include "../../libcryption/include/cryption/dog_cryption.h"
#include "../../libtask/include/task/task.h"
#include "file_check_hash.h"


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

dog_work::TaskPool* task_pool = nullptr;
std::unordered_map<std::string, std::any> turn_std_map(QJsonObject json);
std::vector<std::any> turn_std_list(QJsonArray json);

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

std::vector<std::any> turn_std_list(QJsonArray json)
{
	std::vector<std::any> result(json.size());
	for (uint64_t i = 0; i < json.size(); ++i)
	{
		if (json[i].isBool())
		{
			result[i] = std::make_any<bool>(json[i].toBool());
		}
		else if (isInt(json[i]))
		{
			result[i] = toInt(json[i]);
		}
		else if (json[i].isDouble())
		{
			result[i] = json[i].toDouble();
		}
		else if (json[i].isString())
		{
			result[i] = json[i].toString().toStdString();
		}
		else if (json[i].isArray())
		{
			result[i] = turn_std_list(json[i].toArray());
		}
		else if (json[i].isObject())
		{
			result[i] = turn_std_map(json[i].toObject());
		}
	}
	return result;
}
std::unordered_map<std::string, std::any> turn_std_map(QJsonObject json)
{
	std::unordered_map<std::string, std::any> result;
	for (auto it = json.begin(); it != json.end(); ++it)
	{
		if (it.value().isBool())
		{
			result[it.key().toStdString()] = it.value().toBool();
		}
		else if (isInt(it.value()))
		{
			result[it.key().toStdString()] = toInt(it.value());
		}
		else if (it.value().isDouble())
		{
			result[it.key().toStdString()] = it.value().toDouble();
		}
		else if (it.value().isString())
		{
			result[it.key().toStdString()] = it.value().toString().toStdString();
		}
		else if (it.value().isArray())
		{
			result[it.key().toStdString()] = turn_std_list(it.value().toArray());
		}
		else if (it.value().isObject())
		{
			result[it.key().toStdString()] = turn_std_map(it.value().toObject());
		}
	}
	return result;
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
		try
		{
			std::string std_json_str = jsonstr.toStdString();
			dog_data::JsonObject dog_params = std_json_str;
			dog_param::IOConfig input__config = dog_param::IOConfig(dog_params["input"].get_object(), true);
			dog_param::IOConfig output_config = dog_param::IOConfig(dog_params["output"].get_object(), false);
			
			QJsonObject result;
			dog_work::Timer timer;
			timer.start();
			result["res"] = QString::fromStdString(output_config.fmt_data(input__config.get_data()));
			timer.end();
			result["time"] = timer.get_time();
			result["code"] = 0;
			result["msg"] = "转换成功";
			emit send(QJsonDocument(result).toJson());
			return;
		}
		catch (std::exception& e)
		{
			QJsonObject result;
			result["code"] = 1;
			result["msg"] = QString::fromStdString(e.what()).split("\n").at(0);
			emit send(QJsonDocument(result).toJson());
		}
	}
	void get_data_size(const QString& jsonstr)
	{
		QJsonObject result;
		try
		{
			std::string std_json_str = jsonstr.toStdString();
			dog_data::JsonObject dog_params = std_json_str;
			std::cout << dog_params.to_string(true, 0) << std::endl;
			dog_param::IOConfig input__config = dog_param::IOConfig(dog_params["input"].get_object(), true);
			dog_data::Data data = input__config.get_data();
			result["code"] = 0;
			result["msg"] = "success";
			QJsonValue size = data.size() < 0x20000000000000 ? QJsonValue(data.size() * 1.0) : QJsonValue("overflow");
			result["size"] = size;
			result["id"] = QString::fromStdString(dog_params["id"].get_string());
		}
		catch (std::exception& e)
		{
			result["code"] = 1;
			result["msg"] = QString::fromStdString(e.what()).split("\n").at(0);
		}
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
	void work(const QString& jsonstr)
	{
		QJsonObject result;
		try
		{
			std::string std_json_str = jsonstr.toStdString();
			dog_data::JsonObject dog_params = std_json_str;
			std::cout << dog_params.to_string(true, 0) << std::endl;
			dog_param::IOConfig input__config = dog_param::IOConfig(dog_params["input"].get_object(), true);
			dog_param::IOConfig output_config = dog_param::IOConfig(dog_params["output"].get_object(), false);

			std::unique_ptr<dog_hash::HashConfig> hash_config = nullptr;
			for (auto& single_config : dog_hash::list)
			{
				if (single_config.name == dog_params["type"].get_string())
				{
					hash_config = std::make_unique<dog_hash::HashConfig>(single_config);
					break;
				}
			}
			if (!hash_config)
			{
				throw DOG_EXCEPTION("散列类型错误,不支持的散列类型");
			}
			if (!dog_number::region::is_fall(hash_config->region, dog_params["effective"].get_integer()))
			{
				throw DOG_EXCEPTION("有效输出数不在范围内");
			}
			dog_hash::HashCrypher hash_crypher = dog_hash::HashCrypher(hash_config->name, dog_params["effective"].get_integer());
			if (input__config.is_data())
			{
				dog_work::Timer timer;
				timer.start();
				result["res"] = QString::fromStdString(output_config.fmt_data(hash_crypher.getDataHash(input__config.get_data())));
				timer.end();
				result["time"] = timer.get_time();
				result["msg"] = "散列成功";
			}
			else if (input__config.is_file())
			{
				uint64_t task_id = task_pool->add_hash(input__config,hash_crypher,output_config);
				result["msg"] = QString::fromStdString("任务已添加至队列,任务编号" + std::to_string(task_id));
				result["file"] = true;
			}
			result["code"] = 0;
		}
		catch (std::exception& e)
		{
			result["code"] = 1;
			result["msg"] = QString::fromStdString(e.what()).split("\n").at(0);
		}
		
		emit send_result(QJsonDocument(result).toJson());

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
		dog_work::Timer t;
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
		QJsonObject result;
		try
		{
			std::string std_json_str = jsonstr.toStdString();
			dog_data::JsonObject dog_params = std_json_str;
			std::cout << dog_params.to_string(true, 0) << std::endl;
			dog_param::IOConfig input__config = dog_param::IOConfig(dog_params["io"].get_object()["input"].get_object(), true);
			dog_param::IOConfig output_config = dog_param::IOConfig(dog_params["io"].get_object()["output"].get_object(), false);
			
			dog_data::JsonObject all_config = dog_params["config"].get_object();
			dog_cryption::CryptionConfig config = dog_cryption::CryptionConfig(
				all_config["type"].get_string(), all_config["blockSize"].get_integer(), all_config["keySize"].get_integer(),
				all_config["isPadding"].get_bool(), all_config["padding"].get_string(),
				all_config["mode"].get_string(), true, all_config["shift"].get_integer()
			);

			dog_param::IOConfig key_config = dog_param::IOConfig(dog_params["key"].get_object()["input"].get_object(), true);
			std::unique_ptr<dog_param::IOConfig> iv_config = nullptr;
			auto iv_params = dog_params["iv"].get_object();
			if (iv_params.find("auto") != iv_params.end())
			{
				std::unordered_map<std::string, std::any> iv_params;
				iv_params["ori_str"] = dog_cryption::utils::randiv(config.block_size).getHexString();
				iv_params["type"] = (uint64_t)2;
				iv_params["is_upper"] = true;
				iv_params["is_file"] = false;
				iv_config = std::make_unique<dog_param::IOConfig>(iv_params, true);
			}
			else
			{
				iv_config = std::make_unique<dog_param::IOConfig>(iv_params["input"].get_object(), true);
			}

			dog_data::JsonObject head = dog_params["head"].get_object();
			bool with_check = head["withCheck"].get_bool();
			bool with_config = head["withConfig"].get_bool();
			bool with_iv = head["withIV"].get_bool();

			dog_cryption::Cryptor cryptor = dog_cryption::Cryptor(config);

			dog_data::Data key_data = key_config.get_data();
			dog_data::Data iv_data = iv_config->get_data();

			if (!input__config.is_file())
			{
				dog_data::Data input_data = input__config.get_data();
				result["iv"] = QString::fromStdString(iv_data.getHexString());

				cryptor.set_key(key_data);
				dog_work::Timer timer;
				timer.start();
				dog_data::Data output_data = cryptor.encrypt(input_data, with_config, with_iv, iv_data, with_check);
				timer.end();
				result["time"] = timer.get_time();
				result["res"] = QString::fromStdString(output_config.fmt_data(output_data));
				result["msg"] = "加密成功";
			}
			else
			{
				cryptor.set_key(key_data);
				result["iv"] = QString::fromStdString(iv_data.getHexString());
				uint64_t task_id = task_pool->add_encrypt(
					input__config.get_file_path(), output_config.get_file_path(), cryptor,
					iv_data, with_config, with_iv, with_check
				);
				result["msg"] = QString::fromStdString("任务已添加至队列,任务编号" + std::to_string(task_id));
				result["file"] = true;
			}
			result["code"] = 0;
		}
		catch (dog_exception::Exception& e)
		{
			result["code"] = 1;
			result["msg"] = QString::fromStdString(e.what()).split("\n").at(0);
			std::cout << e.what() << std::endl;
		}
		emit send_result(QJsonDocument(result).toJson());
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
		dog_work::Timer t;
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
		QJsonObject result;
		try
		{
			std::string std_json_str = jsonstr.toStdString();
			dog_data::JsonObject dog_params = std_json_str;
			std::cout << dog_params.to_string(true, 0) << std::endl;
			dog_param::IOConfig input__config = dog_param::IOConfig(dog_params["io"].get_object()["input"].get_object(), true);
			dog_param::IOConfig output_config = dog_param::IOConfig(dog_params["io"].get_object()["output"].get_object(), false);

			dog_data::JsonObject all_config = dog_params["config"].get_object();
			dog_cryption::CryptionConfig config = dog_cryption::CryptionConfig(
				all_config["type"].get_string(), all_config["blockSize"].get_integer(), all_config["keySize"].get_integer(),
				all_config["isPadding"].get_bool(), all_config["padding"].get_string(),
				all_config["mode"].get_string(), true, all_config["shift"].get_integer()
			);

			dog_param::IOConfig key_config = dog_param::IOConfig(dog_params["key"].get_object()["input"].get_object(), true);
			std::unique_ptr<dog_param::IOConfig> iv_config = nullptr;
			auto iv_params = dog_params["iv"].get_object();
			if (iv_params.find("auto") != iv_params.end())
			{
				std::unordered_map<std::string, std::any> iv_params;
				iv_params["ori_str"] = dog_cryption::utils::randiv(config.block_size).getHexString();
				iv_params["type"] = (uint64_t)2;
				iv_params["is_upper"] = true;
				iv_params["is_file"] = false;
				iv_config = std::make_unique<dog_param::IOConfig>(iv_params, true);
			}
			else
			{
				iv_config = std::make_unique<dog_param::IOConfig>(iv_params["input"].get_object(), true);
			}

			dog_data::JsonObject head = dog_params["head"].get_object();
			bool with_check = head["withCheck"].get_bool();
			bool with_config = head["withConfig"].get_bool();
			bool with_iv = head["withIV"].get_bool();

			dog_cryption::Cryptor cryptor = dog_cryption::Cryptor(config);

			dog_data::Data key_data = key_config.get_data();
			dog_data::Data iv_data = iv_config->get_data();

			if (!input__config.is_file())
			{
				dog_data::Data input_data = input__config.get_data();
				result["iv"] = QString::fromStdString(iv_data.getHexString());

				cryptor.set_key(key_data);
				dog_work::Timer timer;
				timer.start();
				dog_data::Data output_data = cryptor.decrypt(input_data, with_config, with_iv, iv_data, with_check);
				timer.end();
				result["time"] = timer.get_time();
				result["res"] = QString::fromStdString(output_config.fmt_data(output_data));
				result["msg"] = "解密成功";
			}
			else
			{
				cryptor.set_key(key_data);
				result["iv"] = QString::fromStdString(iv_data.getHexString());
				uint64_t task_id = task_pool->add_decrypt(
					input__config.get_file_path(), output_config.get_file_path(), cryptor,
					iv_data, with_config, with_iv, with_check
				);
				result["msg"] = QString::fromStdString("任务已添加至队列,任务编号" + std::to_string(task_id));
				result["file"] = true;
			}
			result["code"] = 0;
		}
		catch (dog_exception::Exception& e)
		{
			result["code"] = 1;
			result["msg"] = QString::fromStdString(e.what()).split("\n").at(0);
			std::cout << e.what() << std::endl;
		}
		emit send_result(QJsonDocument(result).toJson());
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
		dog_work::Timer t;
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

	bool check()
	{
		std::string now_path = QCoreApplication::applicationDirPath().toStdString();
		std::vector<std::pair<std::string, std::string>> files_hash = HASH_TABEL;
		dog_hash::HashCrypher crypher("SHA2", 32);
		uint64_t i = 0;
		for (auto& file : files_hash)
		{
			std::string text = "正在校验文件完整性,这可能需要一点时间" + std::to_string(i * 100 / files_hash.size()) + "%";
			this->changeText(QString::fromStdString(text));
			std::string file_path = now_path + file.first.substr(1, -1);
			std::ifstream file_stream(file_path, std::ios::binary);
			if (!file_stream.is_open())
			{
				return false;
			}
			std::string hash_str = dog_hash::HashCrypher::streamHash(crypher, file_stream).getHexString();
			crypher.init();
			if (hash_str != file.second)
			{
				return false;
			}
			i++;
		}
		this->changeText("文件校验成功,正在启动程序......");
		return true;
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
		this->is_effective_ = infoWindow->check();
		if (!this->is_effective_)
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
	
};

int main(int argc, char* argv[])
{
	QApplication app(argc, argv);

	CryptionWindow* window = new CryptionWindow();
	task_pool = new dog_work::TaskPool(8);
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
