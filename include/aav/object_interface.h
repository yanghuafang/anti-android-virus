#ifndef AAV_OBJECT_INTERFACE_H_
#define AAV_OBJECT_INTERFACE_H_

// Common polymorphic base for engine objects. The engine allocates them;
// release one with Destroy(), which runs inside the library so ownership stays
// ABI-safe across compilers and stdlib versions. Callers never `delete` an
// IObject -- the destructor is protected.
namespace aav {

class IObject {
 public:
  virtual void Destroy();

 protected:
  IObject() = default;
  virtual ~IObject() = default;
};

}  // namespace aav

#endif
