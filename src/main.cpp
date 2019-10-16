#include <nan.h>
#include <node.h>

#include "const.h"
#include "node.h"

#include <signal.h>
#include <execinfo.h>

void handler(int sig) {
  void *array[20];
  size_t size;

  // get void*'s for all entries on the stack
  size = backtrace(array, 20);

  // print out all the frames to stderr
  fprintf(stderr, "Error: signal %d:\n", sig);
  char** strings = backtrace_symbols(array, size);

	if (strings) {
		for (size_t i = 0; i < size; i++) {
			fprintf(stderr, "  %s\n", strings[i]);
		}
		free(strings);
	}

  exit(1);
}



NAN_MODULE_INIT(init)
{
	signal(SIGSEGV, handler);

	Nan::HandleScope scope;

	WPKCS11::Init(target);

	declare_objects(target);
	declare_attributes(target);
	declare_ket_types(target);
	declare_mechanisms(target);
	declare_flags(target);
	declare_certificates(target);
	declare_mgf(target);
	declare_kdf(target);
	declare_params(target);
	declare_initialize_flags(target);
	declare_user_types(target);
}

NODE_MODULE(pkcs11, init)
