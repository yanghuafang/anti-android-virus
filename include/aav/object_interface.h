#ifndef AAV_OBJECT_INTERFACE_H_
#define AAV_OBJECT_INTERFACE_H_

namespace aav {

/// Common polymorphic base for engine objects. The engine allocates them;
/// release one with Destroy(), which runs inside the library so ownership stays
/// ABI-safe across compilers and stdlib versions. The protected destructor is
/// what makes `delete` on an IObject a compile error rather than a convention.
class IObject {
 public:
  /// Destroy this object. Runs `delete this` inside the library, so the caller
  /// never links an operator delete for an engine type.
  virtual void Destroy();

  /// Deleted here rather than per class: every interface and implementation
  /// below inherits it, so a slicing copy is a compile error throughout.
  /// Public so the diagnostic names the deleted function, not an access error.
  IObject(const IObject&) = delete;
  IObject& operator=(const IObject&) = delete;

 protected:
  IObject() = default;
  virtual ~IObject() = default;
};

}  // namespace aav

#endif
