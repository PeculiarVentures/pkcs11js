#include "template.h"

static void attr_set_value(CK_ATTRIBUTE_PTR attr, const char* value, uint32_t valueLen) {
	try {
		attr->pValue = (char*)malloc(valueLen);
		memcpy(attr->pValue, value, valueLen);
		attr->ulValueLen = valueLen;
	}
	CATCH_ERROR;
}

static Scoped<CK_ATTRIBUTE> v2c_ATTRIBUTE(Local<Value> v8Attribute) {
    Nan::HandleScope scope;
    
	try {
		if (!v8Attribute->IsObject()) {
			THROW_ERROR("Parameter 1 MUST be Object", NULL);
		}

        Local<Object> v8Object = Nan::To<v8::Object>(v8Attribute).ToLocalChecked();

        Local<Value> v8Type = Nan::Get(v8Object, Nan::New(STR_TYPE).ToLocalChecked()).ToLocalChecked();
		if (!v8Type->IsNumber()) {
			THROW_ERROR("Member 'type' MUST be Number", NULL);
		}

        Local<Value> v8Value = Nan::Get(v8Object, Nan::New(STR_VALUE).ToLocalChecked()).ToLocalChecked();
		if (!(v8Value->IsUndefined() || v8Value->IsNull() ||
			node::Buffer::HasInstance(v8Value) ||
			v8Value->IsBoolean() ||
			v8Value->IsString() ||
			v8Value->IsNumber())) {
			THROW_ERROR("Member 'value' MUST has wrong type", NULL);
		}

		Scoped<CK_ATTRIBUTE> attr(new CK_ATTRIBUTE());
		attr->pValue = NULL;
		attr->ulValueLen = 0;

		attr->type = Nan::To<uint32_t>(v8Type).FromJust();
		if (node::Buffer::HasInstance(v8Value)) {
			// Buffer
			GET_BUFFER_SMPL(data, v8Value);
			attr_set_value(attr.get(), data, (uint32_t)dataLen);
		}
		else if (v8Value->IsBoolean()) {
			// Boolean
			char data[1];
            data[0] = (char)Nan::To<bool>(v8Value).FromJust();
			attr_set_value(attr.get(), data, 1);
		}
		else if (v8Value->IsNumber()) {
			// Number
			CK_ULONG num = (CK_ULONG)Nan::To<uint32_t>(v8Value).FromJust();

			uint32_t long_size = sizeof(CK_ULONG);

			attr->pValue = (char*)malloc(long_size);
			*(CK_ULONG*)attr->pValue = num;
			attr->ulValueLen = long_size;
		}
		else if (v8Value->IsString()) {
			// String
            Nan::Utf8String utf8Val(v8Value);
			char* val = *utf8Val;
			int valLen = utf8Val.length();
			attr_set_value(attr.get(), val, valLen);
		}

		return attr;
	}
	CATCH_ERROR;
}

static Local<Object> c2v_ATTRIBUTE(CK_ATTRIBUTE_PTR attr) {
    Nan::EscapableHandleScope scope;
    
	try {
		if (!attr) {
			THROW_ERROR("Parameter 1 is EMPTY", NULL);
		}

		Local<Object> v8Attribute = Nan::New<Object>();

		// Type
        Nan::Set(v8Attribute, Nan::New(STR_TYPE).ToLocalChecked(), Nan::New<Number>(attr->type));

		// Value
		Local<Object> v8Value = node::Buffer::Copy(Isolate::GetCurrent(), (char *)attr->pValue, attr->ulValueLen).ToLocalChecked();
        Nan::Set(v8Attribute, Nan::New(STR_VALUE).ToLocalChecked(), v8Value);

		return scope.Escape(v8Attribute);
	}
	CATCH_ERROR;
}

static void TEMPLATE_free(TEMPLATE* tmpl) {
	if (tmpl && tmpl->items) {
		// Free attr values
		for (CK_ULONG i = 0; i < tmpl->size; i++) {
			if (&tmpl->items[i] && tmpl->items[i].pValue) {
				free(tmpl->items[i].pValue);
			}
		}
		free(tmpl->items);
	}
}

Attributes::Attributes() {
	data = TEMPLATE();
	data.size = 0;
	data.items = NULL;
}

Attributes::~Attributes() {
	TEMPLATE_free(Get());
}

TEMPLATE* Attributes::New() {
	TEMPLATE_free(Get());
	data = TEMPLATE();
	data.size = 0;
	data.items = NULL;
	return Get();
}

void Attributes::Push(CK_ATTRIBUTE_PTR attr) {
	try {
		if (!attr)
			THROW_ERROR("Parameter 1 is EMPTY", NULL);
		if (Get()) {
			data.items = (CK_ATTRIBUTE_PTR)realloc(data.items, ++data.size * sizeof(CK_ATTRIBUTE));
			data.items[data.size - 1] = *(attr);
		}
	}
	CATCH_ERROR;
}

void Attributes::FromV8(Local<Value> v8Value) {
    Nan::HandleScope scope;
    
	try {
		if (!v8Value->IsArray()) {
			THROW_ERROR("Parameter 1 MUST be Array", NULL);
		}

		Local<Object> v8Template = Nan::To<v8::Object>(v8Value).ToLocalChecked();
        
        Local<Value> v8TemplateLen = Nan::Get(v8Template, Nan::New("length").ToLocalChecked()).ToLocalChecked();
		uint32_t templateLen = Nan::To<uint32_t>(v8TemplateLen).FromJust();

		uint32_t i = 0;
		New();
		for (i = 0; i < templateLen; i++) {
            Local<Value> v8Attribute = Nan::Get(v8Template, i).ToLocalChecked();
			Scoped<CK_ATTRIBUTE> attr = v2c_ATTRIBUTE(v8Attribute);
			this->Push(attr.get());
		}
	}
	CATCH_ERROR;
}

Local<Object> Attributes::ToV8() {
    Nan::EscapableHandleScope scope;
    
	try {
		Local<Array> v8Res = Nan::New<Array>();
		for (uint32_t i = 0; i < data.size; i++) {
			CK_ATTRIBUTE_PTR pItem = &data.items[i];
			Local<Object> v8Attribute = c2v_ATTRIBUTE(pItem);

            Nan::Set(v8Res, i, v8Attribute);
		}
		return scope.Escape(v8Res);
	}
	CATCH_ERROR;
}
