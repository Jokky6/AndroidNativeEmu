from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
from androidemu.java.java_field_def import JavaFieldDef

class java_lang_String(metaclass=JavaClassDef, jvm_name="java/lang/String"):
    def __init__(self, _value):
        self.value = _value

    @java_method_def(name='getBytes', signature='(Ljava/lang/String;)[B', native=False, args_list=['jstring'])
    def getBytes(self, *args, **kwargs):
        print(args)

        return bytearray(self.value.encode(args[1].value.value))

    def __len__(self):
        return len(self.value)

    def __str__(self):
        return self.value



