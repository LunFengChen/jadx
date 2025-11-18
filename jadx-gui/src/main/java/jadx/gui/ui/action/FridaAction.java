package jadx.gui.ui.action;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

import org.apache.commons.text.StringEscapeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jadx.api.JavaClass;
import jadx.api.JavaField;
import jadx.api.JavaMethod;
import jadx.api.metadata.annotations.VarNode;
import jadx.core.codegen.TypeGen;
import jadx.core.dex.info.MethodInfo;
import jadx.core.dex.instructions.args.ArgType;
import jadx.core.dex.nodes.MethodNode;
import jadx.core.utils.StringUtils;
import jadx.core.utils.exceptions.JadxRuntimeException;
import jadx.gui.treemodel.JClass;
import jadx.gui.treemodel.JField;
import jadx.gui.treemodel.JMethod;
import jadx.gui.treemodel.JNode;
import jadx.gui.ui.codearea.CodeArea;
import jadx.gui.ui.dialog.MethodsDialog;
import jadx.gui.utils.NLS;
import jadx.gui.utils.UiUtils;

public final class FridaAction extends JNodeAction {
	private static final Logger LOG = LoggerFactory.getLogger(FridaAction.class);
	private static final long serialVersionUID = -3084073927621269039L;

	public FridaAction(CodeArea codeArea) {
		super(ActionModel.FRIDA_COPY, codeArea);
	}

	@Override
	public void runAction(JNode node) {
		try {
			generateFridaSnippet(node);
		} catch (Exception e) {
			LOG.error("Failed to generate Frida code snippet", e);
			JOptionPane.showMessageDialog(getCodeArea().getMainWindow(), e.getLocalizedMessage(), NLS.str("error_dialog.title"),
					JOptionPane.ERROR_MESSAGE);
		}
	}

	@Override
	public boolean isActionEnabled(JNode node) {
		return node instanceof JMethod || node instanceof JClass || node instanceof JField;
	}

	private void generateFridaSnippet(JNode node) {
		String fridaSnippet;
		if (node instanceof JMethod) {
			fridaSnippet = generateMethodSnippet((JMethod) node);
			copySnipped(fridaSnippet);
		} else if (node instanceof JField) {
			fridaSnippet = generateFieldSnippet((JField) node);
			copySnipped(fridaSnippet);
		} else if (node instanceof JClass) {
			SwingUtilities.invokeLater(() -> showMethodSelectionDialog((JClass) node));
		} else {
			throw new JadxRuntimeException("Unsupported node type: " + (node != null ? node.getClass() : "null"));
		}

	}

	private void copySnipped(String fridaSnippet) {
		if (!StringUtils.isEmpty(fridaSnippet)) {
			LOG.info("Frida snippet:\n{}", fridaSnippet);
			UiUtils.copyToClipboard(fridaSnippet);
		}
	}

	private String generateMethodSnippet(JMethod jMth) {
		return getMethodSnippet(jMth.getJavaMethod(), jMth.getJParent());
	}

	private String generateMethodSnippet(JavaMethod javaMethod, JClass jc) {
		return getMethodSnippet(javaMethod, jc);
	}

	private String getMethodSnippet(JavaMethod javaMethod, JClass jc) {
		MethodNode mth = javaMethod.getMethodNode();
		MethodInfo methodInfo = mth.getMethodInfo();

		// 获取方法签名用于检测参数类型（解决泛型信息丢失问题）
		// 对于 native 方法，getCodeStr() 返回空，使用 toString() 获取完整签名
		String methodSignature = javaMethod.toString();
		if (methodSignature == null || methodSignature.isEmpty()) {
			methodSignature = mth.toString();
		}
		
		// 获取 Smali 格式的方法签名用于添加注释
		String smaliSignature = methodInfo.makeSignature(true);

		String methodName;
		// 处理构造方法
		if (methodInfo.isConstructor()) {
			methodName = "$init";
		} else {
			methodName = StringEscapeUtils.escapeEcmaScript(methodInfo.getName());
		}

		// 处理重载方法: overload
		String overload = isOverloaded(mth) ? ".overload(" +
				methodInfo.getArgumentsTypes().stream()
						.map(this::parseArgType).collect(Collectors.joining(", ")) + ")" : "";

		List<String> argNames = mth.collectArgNodes().stream()
				.map(VarNode::getName).collect(Collectors.toList());
		String args = String.join(", ", argNames);
		String logArgs = argNames.isEmpty() ? "no args!" :
				"args are as follows:\\n" + argNames.stream()
						.map(arg -> "    ->" + arg + "= ${" + arg + "}")
						.collect(Collectors.joining("\\n"));

		// 改成完整类名, 防止变量重复的可能
		String fullClassName = mth.getParentClass().getFullName().replace(".", "_");

		// 检查是否匹配常用担不便于阅读的参数: Map, ByteArray, StringArray
		// hasMapParameter, hasByteArrayParameter, hasStringArrayParameter
		List<ArgType> argTypes = methodInfo.getArgumentsTypes();

		// 调试日志：打印参数类型信息
		LOG.info("=== Frida Method Analysis: {} ===", methodInfo.getName());
		LOG.info("Method signature: {}", methodSignature);
		LOG.info("Arguments count: {}", argTypes.size());
		for (int i = 0; i < argTypes.size(); i++) {
			ArgType argType = argTypes.get(i);
			LOG.info("  Arg[{}]: {}", i, argType);
			LOG.info("    isGeneric={}, isArray={}, isObject={}", argType.isGeneric(), argType.isArray(), argType.isObject());
			if (argType.isGeneric() && argType.getGenericTypes() != null) {
				LOG.info("    GenericTypes count: {}", argType.getGenericTypes().size());
				for (int j = 0; j < argType.getGenericTypes().size(); j++) {
					ArgType gt = argType.getGenericTypes().get(j);
					LOG.info("      GenericType[{}]: {}, isArray={}", j, gt, gt.isArray());
					if (gt.isArray()) {
						LOG.info("        ArrayElement: {}", gt.getArrayElement());
					}
				}
			}
		}
		boolean hasMapParameter = argTypes.stream()
				.anyMatch(argType -> argType.isObject() &&
						(argType.getObject().contains("Map") ||
								argType.getObject().contains("HashMap") ||
								argType.getObject().contains("TreeMap")));

		// 检查直接参数或泛型参数中是否包含 byte[]
		// 由于泛型信息可能丢失，使用方法签名字符串来检测
		boolean hasByteArrayParameter = argTypes.stream()
				.anyMatch(argType -> {
					// 检查直接参数是否是 byte[]
					if (argType.isArray() && argType.getArrayElement().equals(ArgType.BYTE)) {
						return true;
					}
					// 检查泛型参数（如 Map<String, byte[]>）
					if (argType.isGeneric() && argType.getGenericTypes() != null) {
						return argType.getGenericTypes().stream()
								.anyMatch(genericType -> genericType.isArray() && genericType.getArrayElement().equals(ArgType.BYTE));
					}
					return false;
				});
		// 如果 ArgType 检测失败，使用方法签名字符串作为后备方案
		if (!hasByteArrayParameter && methodSignature != null) {
			hasByteArrayParameter = methodSignature.contains("byte[]");
			LOG.info("Using fallback detection for byte[]: {}", hasByteArrayParameter);
		}

		// 检查直接参数或泛型参数中是否包含 String[]
		boolean hasStringArrayParameter = argTypes.stream()
				.anyMatch(argType -> {
					// 检查直接参数是否是 String[]
					if (argType.isArray() && argType.getArrayElement().equals(ArgType.STRING)) {
						return true;
					}
					// 检查泛型参数（如 Map<String, String[]>）
					if (argType.isGeneric() && argType.getGenericTypes() != null) {
						return argType.getGenericTypes().stream()
								.anyMatch(genericType -> genericType.isArray() && genericType.getArrayElement().equals(ArgType.STRING));
					}
					return false;
				});
		// 如果 ArgType 检测失败，使用方法签名字符串作为后备方案
		if (!hasStringArrayParameter && methodSignature != null) {
			hasStringArrayParameter = methodSignature.contains("String[]");
			LOG.info("Using fallback detection for String[]: {}", hasStringArrayParameter);
		}

		// 输出检测结果
		LOG.info("Detection results:");
		LOG.info("  hasMapParameter: {}", hasMapParameter);
		LOG.info("  hasByteArrayParameter: {}", hasByteArrayParameter);
		LOG.info("  hasStringArrayParameter: {}", hasStringArrayParameter);

		// 构建辅助函数
		int helperFuncIndex = 1;
		String helperFunctions = getHelpfunction("showJavaStacks", helperFuncIndex++);
		if (hasMapParameter) {
			helperFunctions += getHelpfunction("showJavaMap", helperFuncIndex++);
		}
		if (hasByteArrayParameter) {
			helperFunctions += getHelpfunction("bytesToString", helperFuncIndex++);
		}
		if (hasStringArrayParameter) {
			helperFunctions += getHelpfunction("showStringArray", helperFuncIndex++);
		}
		// 添加Map参数显示逻辑
		StringBuilder mapLogging = new StringBuilder();
		if (hasMapParameter) {
			for (int i = 0; i < argNames.size(); i++) {
				ArgType argType = argTypes.get(i);
				String argName = argNames.get(i);
				if (argType.isObject() &&
						(argType.getObject().contains("Map") ||
								argType.getObject().contains("HashMap") ||
								argType.getObject().contains("TreeMap"))) {
					mapLogging.append("            showJavaMap(").append(argName).append(", \"").append(argName).append("\");\n");
				}
			}
		}

		// 使用三目运算符判断是否有返回值
		boolean hasReturnValue = !(methodInfo.isConstructor() || methodInfo.getReturnType() == ArgType.VOID);
		String newMethodName = methodInfo.isConstructor() ? methodName : StringEscapeUtils.escapeEcmaScript(methodInfo.getAlias());

		// 使用三目运算符构建函数实现体
		String functionImplementation = "        " + fullClassName + "[\"" + methodName + "\"]" + overload + ".implementation = function (" + args + ") {\n" +
				"            console.log(`[->] " + fullClassName + "." + newMethodName + " is called! " + logArgs + "`);\n" +
				mapLogging.toString() +
				(hasReturnValue ?
						"            var retval = this[\"" + methodName + "\"](" + args + ");\n" +
								"            // showJavaStacks();\n" +
								"            console.log(`[<-] " + fullClassName + "." + newMethodName + " ended! \\n    retval= ${retval}`);\n" +
								"            return retval;\n"
						:
						"            this[\"" + methodName + "\"](" + args + ");\n" +
								"            // showJavaStacks();\n" +
								"            console.log(`[<-] " + fullClassName + "." + newMethodName + " ended! no retval!`);\n") +
				"        };\n";

		return "// Smali signature: " + smaliSignature + "\n" +
				"function hook_mointor_" + methodName + "(){\n" +
				"    Java.perform(function () {\n" +
				"        " + String.format("let %s = Java.use(\"%s\");\n", fullClassName, mth.getParentClass().getFullName()) +
				functionImplementation +
				"    });\n" +
				helperFunctions +
				"    console.warn(`[*] hook_mointor_" + methodName + " is injected!`);\n" +
				"};\n" +
				"hook_mointor_" + methodName + "();\n";

	}

	private String getHelpfunction(String functionName, int functionIndex) {
		switch (functionName) {
			case "showJavaStacks":
				return "    // 辅助函数" + functionIndex + ": 打印调用栈\n" +
						"    function showJavaStacks() {\n" +
						"        console.log(Java.use(\"android.util.Log\").getStackTraceString(Java.use(\"java.lang.Exception\").$new()));\n" +
						"    };\n";
			case "showJavaMap":
				return "    // 辅助函数" + functionIndex + ": 打印Map\n" +
						"    function showJavaMap(map, mapName) {\n" +
						"        if (map == null) return;\n" +
						"        console.log(mapName + ', Map content:');\n" +
						"        var keys = map.keySet().toArray();\n" +
						"        for (var i = 0; i < keys.length; i++) {\n" +
						"            var key = keys[i];\n" +
						"            var value = map.get(key);\n" +
						"            var value_str = \"\";\n" +
						"            if (value != null && value.getClass().getName() === \"[B\") {\n" +
						"                value_str = Java.use('java.lang.String').$new(Java.array('byte', value)).toString();\n" +
						"            } else {\n" +
						"                value_str = value;\n" +
						"            }\n" +
						"            console.log('  ' + key + ' = ' + value_str);\n" +
						"        }\n" +
						"    }\n";
			case "bytesToString":
				/*
						"    // (1) method 1\n" +
						"    // return Java.use('java.lang.String').$new(Java.array('byte', Java.cast(value, Java.use('[B')))).toString();\n" +
						"    // (2) method 2\n" +
						"    // var JavaClass_ByteString = Java.use('com.android.okhttp.okio.ByteString');\n" +
						"    // return JavaClass_ByteString.of.overload('[B').call(JavaClass_ByteString, value).utf8();\n" +
				*/
				return "    // 辅助函数" + functionIndex + ": 字节数组转字符串\n" +
						"    function bytesToString(bArr) {\n" +
						"        return Java.use('java.lang.String').$new(Java.array('byte', bArr)).toString();\n" +
						"    };\n";
			case "showStringArray":
				return "    // 辅助函数" + functionIndex + ": 打印字符串数组\n" +
						"    function showStringArray(strArr) {\n" +
						"        if (strArr == null) return;\n" +
						"        var JavaClass_Array = Java.use('java.lang.reflect.Array');\n" +
						"        var length = JavaClass_Array.getLength(strArr);\n" +
						"        console.log('String array length: ' + length);\n" +
						"        for (let i = 0; i < length; i++) {\n" +
						"            var item = JavaClass_Array.get(strArr, i);\n" +
						"            console.log('  [' + i + '] = ' + (item != null ? item.toString() : 'null'));\n" +
						"        }\n" +
						"    }\n";
			default:
				return "";
		}

	}

	private String generateClassSnippet(JClass jc) {
		JavaClass javaClass = jc.getCls();
		String rawClassName = StringEscapeUtils.escapeEcmaScript(javaClass.getRawName());
		// String shortClassName = javaClass.getName();
		String fullClassName = javaClass.getFullName().replace(".", "_");
		return String.format("var %s = Java.use(\"%s\");", fullClassName, rawClassName);
	}

	private void showMethodSelectionDialog(JClass jc) {
		JavaClass javaClass = jc.getCls();
		new MethodsDialog(getCodeArea().getMainWindow(), javaClass.getMethods(), (result) -> {
			String fridaSnippet = generateClassAllMethodSnippet(jc, result);
			copySnipped(fridaSnippet);
		});
	}

	private String generateClassAllMethodSnippet(JClass jc, List<JavaMethod> methodList) {
		JavaClass javaClass = jc.getCls();
		String rawClassName = javaClass.getFullName();
		String fullClassName = rawClassName.replace(".", "_");
		String functionName = "hook_" + fullClassName;
		
		// 收集所有需要的辅助函数类型
		boolean needsShowJavaStacks = true; // 总是包含
		boolean needsShowJavaMap = false;
		boolean needsBytesToString = false;
		boolean needsShowStringArray = false;
		
		// 分析所有方法的参数类型
		for (JavaMethod javaMethod : methodList) {
			MethodNode mth = javaMethod.getMethodNode();
			MethodInfo methodInfo = mth.getMethodInfo();
			
			// 获取方法签名用于检测参数类型
			String methodSignature = javaMethod.toString();
			if (methodSignature == null || methodSignature.isEmpty()) {
				methodSignature = mth.toString();
			}
			
			List<ArgType> argTypes = methodInfo.getArgumentsTypes();
			
			// 检查 Map 参数
			if (!needsShowJavaMap) {
				needsShowJavaMap = argTypes.stream()
						.anyMatch(argType -> argType.isObject() &&
								(argType.getObject().contains("Map") ||
										argType.getObject().contains("HashMap") ||
										argType.getObject().contains("TreeMap")));
			}
			
			// 检查 byte[] 参数
			if (!needsBytesToString && methodSignature != null) {
				needsBytesToString = methodSignature.contains("byte[]");
			}
			
			// 检查 String[] 参数
			if (!needsShowStringArray && methodSignature != null) {
				needsShowStringArray = methodSignature.contains("String[]");
			}
		}
		
		// 构建辅助函数
		StringBuilder helperFunctions = new StringBuilder();
		int helperIndex = 1;
		helperFunctions.append(getHelpfunction("showJavaStacks", helperIndex++));
		if (needsShowJavaMap) {
			helperFunctions.append(getHelpfunction("showJavaMap", helperIndex++));
		}
		if (needsBytesToString) {
			helperFunctions.append(getHelpfunction("bytesToString", helperIndex++));
		}
		if (needsShowStringArray) {
			helperFunctions.append(getHelpfunction("showStringArray", helperIndex++));
		}
		
		// 构建所有方法的 hook 函数
		StringBuilder methodFunctions = new StringBuilder();
		StringBuilder methodCalls = new StringBuilder();
		
		for (JavaMethod javaMethod : methodList) {
			MethodNode mth = javaMethod.getMethodNode();
			MethodInfo methodInfo = mth.getMethodInfo();
			
			// 跳过 <clinit> 静态初始化方法
			if (methodInfo.isClassInit()) {
				continue;
			}
			
			String methodName;
			if (methodInfo.isConstructor()) {
				methodName = "$init";
			} else {
				methodName = StringEscapeUtils.escapeEcmaScript(methodInfo.getName());
			}
			
			String hookFunctionName = "hook_method_" + methodName;
			String methodImpl = generateMethodImplementation(javaMethod, fullClassName);
			
			if (methodImpl != null && !methodImpl.isEmpty()) {
				// 生成方法 hook 函数
				methodFunctions.append("        function ").append(hookFunctionName).append("() {\n");
				methodFunctions.append(methodImpl).append("\n");
				methodFunctions.append("            console.warn(`[*] ").append(hookFunctionName).append(" is injected!`);\n");
				methodFunctions.append("        }\n\n");
				
				// 添加调用
				methodCalls.append("        ").append(hookFunctionName).append("();\n");
			}
		}
		
		// 构建完整的类 hook 函数
		return "function " + functionName + "(){\n" +
				"    Java.perform(function () {\n" +
				"        let " + fullClassName + " = Java.use(\"" + rawClassName + "\");\n\n" +
				methodCalls.toString() + "\n" +
				methodFunctions.toString() +
				"    });\n" +
				helperFunctions.toString() +
				"    console.warn(`[*] " + functionName + " is injected!`);\n" +
				"};\n" +
				functionName + "();\n";
	}

	private String generateMethodImplementation(JavaMethod javaMethod, String fullClassName) {
		MethodNode mth = javaMethod.getMethodNode();
		MethodInfo methodInfo = mth.getMethodInfo();
		
		// 获取 Smali 格式的方法签名
		String smaliSignature = methodInfo.makeSignature(true);
		
		String methodName;
		// 处理构造方法和静态初始化方法
		if (methodInfo.isConstructor()) {
			methodName = "$init";
		} else if (methodInfo.isClassInit()) {
			methodName = "$clinit";
		} else {
			methodName = StringEscapeUtils.escapeEcmaScript(methodInfo.getName());
		}
		
		// 处理重载方法
		String overload = isOverloaded(mth) ? ".overload(" +
				methodInfo.getArgumentsTypes().stream()
						.map(this::parseArgType).collect(Collectors.joining(", ")) + ")" : "";
		
		List<String> argNames = mth.collectArgNodes().stream()
				.map(VarNode::getName).collect(Collectors.toList());
		String args = String.join(", ", argNames);
		String logArgs = argNames.isEmpty() ? "no args!" :
				"args are as follows:\\n" + argNames.stream()
						.map(arg -> "    ->" + arg + "= ${" + arg + "}")
						.collect(Collectors.joining("\\n"));
		
		// 检查是否有 Map 参数需要打印
		List<ArgType> argTypes = methodInfo.getArgumentsTypes();
		StringBuilder mapLogging = new StringBuilder();
		for (int i = 0; i < argNames.size(); i++) {
			if (i < argTypes.size()) {
				ArgType argType = argTypes.get(i);
				String argName = argNames.get(i);
				if (argType.isObject() &&
						(argType.getObject().contains("Map") ||
								argType.getObject().contains("HashMap") ||
								argType.getObject().contains("TreeMap"))) {
					mapLogging.append("                showJavaMap(").append(argName).append(", \"").append(argName).append("\");\n");
				}
			}
		}
		
		// 判断是否有返回值
		boolean hasReturnValue = !(methodInfo.isConstructor() || methodInfo.getReturnType() == ArgType.VOID);
		String newMethodName = methodInfo.isConstructor() ? methodName : StringEscapeUtils.escapeEcmaScript(methodInfo.getAlias());
		
		// 构建方法 implementation（用于嵌套在 function 内部，所以使用 3 级缩进）
		String implementation = "            // Smali: " + smaliSignature + "\n" +
				"            " + fullClassName + "[\"" + methodName + "\"]" + overload + ".implementation = function (" + args + ") {\n" +
				"                console.log(`[->] " + fullClassName + "." + newMethodName + " is called! " + logArgs + "`);\n" +
				mapLogging.toString() +
				(hasReturnValue ?
						"                var retval = this[\"" + methodName + "\"](" + args + ");\n" +
								"                // showJavaStacks();\n" +
								"                console.log(`[<-] " + fullClassName + "." + newMethodName + " ended! \\n    retval= ${retval}`);\n" +
								"                return retval;\n"
						:
						"                this[\"" + methodName + "\"](" + args + ");\n" +
								"                // showJavaStacks();\n" +
								"                console.log(`[<-] " + fullClassName + "." + newMethodName + " ended! no retval!`);\n") +
				"            };";
		
		return implementation;
	}

	private String generateFieldSnippet(JField jf) {
		JavaField javaField = jf.getJavaField();
		String rawFieldName = StringEscapeUtils.escapeEcmaScript(javaField.getRawName());
		String fieldName = javaField.getName();

		List<MethodNode> methodNodes = javaField.getFieldNode().getParentClass().getMethods();
		for (MethodNode methodNode : methodNodes) {
			if (methodNode.getName().equals(rawFieldName)) {
				rawFieldName = "_" + rawFieldName;
				break;
			}
		}
		JClass jc = jf.getRootClass();
		String classSnippet = generateClassSnippet(jc);
		return String.format("%s\n%s = %s.%s.value;", classSnippet, fieldName, jc.getName(), rawFieldName);
	}

	public Boolean isOverloaded(MethodNode methodNode) {
		return methodNode.getParentClass().getMethods().stream()
				.anyMatch(m -> m.getName().equals(methodNode.getName())
						&& !Objects.equals(methodNode.getMethodInfo().getShortId(), m.getMethodInfo().getShortId()));
	}

	private String parseArgType(ArgType x) {
		String typeStr;
		if (x.isArray()) {
			typeStr = TypeGen.signature(x).replace("/", ".");
		} else {
			typeStr = x.toString();
		}
		return "'" + typeStr + "'";
	}
}
