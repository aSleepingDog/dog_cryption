#include "task/task.h"

/*
* UniqueObject 懒汉式单例
* @tparam T 需要单例的对象
* @tparam Args 构造函数参数类型
*/
template<typename T, typename... Args>
class UniqueObject
{
private:
	UniqueObject(const UniqueObject&) = delete;
	UniqueObject(const UniqueObject&&) = delete;
	UniqueObject(UniqueObject&) = delete;
	UniqueObject(UniqueObject&&) = delete;
public:
	static T& get(Args&&... args)
	{
		static T* obj = new T(std::forward<Args>(args)...);
		return *obj;
	}
};

using UniqueTaskPool = UniqueObject<dog_work::TaskPool, uint64_t>;
