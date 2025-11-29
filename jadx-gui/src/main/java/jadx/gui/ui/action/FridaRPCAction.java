package jadx.gui.ui.action;

import java.util.ArrayList;
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

public final class FridaRPCAction extends JNodeAction {
	private static final Logger LOG = LoggerFactory.getLogger(FridaRPCAction.class);

	public FridaRPCAction(CodeArea codeArea) {
		super(ActionModel.FRIDA_RPC_COPY, codeArea);
	}

	@Override
	public void runAction(JNode node) {
		try {
			generateFridaRPCSnippet(node);
		} catch (Exception e) {
			LOG.error("Failed to generate Frida RPC code", e);
			JOptionPane.showMessageDialog(getCodeArea().getMainWindow(), e.getLocalizedMessage(), NLS.str("error_dialog.title"),
					JOptionPane.ERROR_MESSAGE);
		}
	}

	@Override
	public boolean isActionEnabled(JNode node) {
		return node instanceof JMethod || node instanceof JClass || node instanceof JField;
	}

	private void generateFridaRPCSnippet(JNode node) {
		String fridaRPCSnippet;
		// 目前只支持某个方法
		if (node instanceof JMethod) {
			fridaRPCSnippet = generateMethodSnippet((JMethod) node);
			copySnipped(fridaRPCSnippet);
		} else {
			throw new JadxRuntimeException("Unsupported node type: " + (node != null ? node.getClass() : "null"));
		}

	}

	private void copySnipped(String fridaRPCSnippet) {
		if (!StringUtils.isEmpty(fridaRPCSnippet)) {
			LOG.info("Frida RPC snippet:\n{}", fridaRPCSnippet);
			UiUtils.copyToClipboard(fridaRPCSnippet);
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
		String overload = "";
		String overloadArgs = "";
		if (isOverloaded(mth)) {
			String argsStr = methodInfo.getArgumentsTypes().stream()
					.map(this::parseArgType).collect(Collectors.joining(", "));
			overload = ".overload(" + argsStr + ")";
			overloadArgs = "(" + argsStr + ")";
		}

		List<String> argNames = mth.collectArgNodes().stream()
				.map(VarNode::getName).collect(Collectors.toList());

		// 生成参数变量名列表 (arg1, arg2, ...)
		List<String> argVars = new ArrayList<>();
		for (int i = 0; i < argNames.size(); i++) {
			argVars.add("arg" + (i + 1) + "_" + argNames.get(i));
		}
		String args = String.join(", ", argVars);

		// 改成完整类名, 防止变量重复的可能
		String fullClassName = mth.getParentClass().getFullName().replace(".", "_");

		// 判断是否为非静态方法（需要实例化）
		boolean isInstanceMethod = !mth.getAccessFlags().isStatic() && !methodInfo.isConstructor();
		
		// 获取参数类型列表
		List<ArgType> argTypes = methodInfo.getArgumentsTypes();
		
		// 构建参数声明部分
		StringBuilder paramDeclarations = new StringBuilder();
		boolean hasContextParam = false;
		if (!argVars.isEmpty()) {
			paramDeclarations.append("        // please check your args! you can hook this function to get example args\n");
			
			// 检查是否有Context类型的参数
			for (int i = 0; i < argVars.size(); i++) {
				if (i < argTypes.size()) {
					ArgType argType = argTypes.get(i);
					if (isContextType(argType)) {
						hasContextParam = true;
						break;
					}
				}
			}
			
			// 如果有Context参数，先生成获取Context的代码
			if (hasContextParam) {
				paramDeclarations.append("        var context = Java.use(\"android.app.ActivityThread\").currentApplication().getApplicationContext();\n");
			}
			
			// 生成每个参数的声明
			for (int i = 0; i < argVars.size(); i++) {
				String argVar = argVars.get(i);
				if (i < argTypes.size()) {
					ArgType argType = argTypes.get(i);
					if (isContextType(argType)) {
						// 如果是Context类型，使用获取到的context
						paramDeclarations.append("        var ").append(argVar).append(" = context;\n");
					} else {
						// 其他类型使用占位符
						paramDeclarations.append("        var ").append(argVar).append(" = ?;\n");
					}
				} else {
					paramDeclarations.append("        var ").append(argVar).append(" = ?;\n");
				}
			}
			paramDeclarations.append("\n");
		}

		// 使用三目运算符处理有无返回值的情况
		boolean hasReturnValue = !(methodInfo.isConstructor() || methodInfo.getReturnType() == ArgType.VOID);
		
		// 对于实例方法，使用 instance 调用；对于静态方法，使用类名调用
		String caller = isInstanceMethod ? "instance" : fullClassName;
		String callStatement = hasReturnValue
				? "var retval = " + caller + "[\"" + methodName + "\"]" + overload + "(" + args + ");"
				: caller + "[\"" + methodName + "\"]" + overload + "(" + args + ");";

		String logStatement = hasReturnValue
				? "console.warn(`[*] " + fullClassName + "." + methodName + " is called! \\nretval= ${retval}`);"
				: "console.warn(`[*] " + fullClassName + "." + methodName + " is called! no retval!`);";

		// 构建主动调用函数体
		String functionBody = "function call_" + methodName	 + "(){\n"
				+ "    " + (hasReturnValue ? "return " : "") + "Java.perform(function () {\n"
				+ "        // Smali signature: " + smaliSignature + "\n"
				+ "        " + String.format("let %s = Java.use(\"%s\");\n", fullClassName, mth.getParentClass().getFullName())
				+ (isInstanceMethod
						? "        // you should hava a instance to call func, please check init func's args\n"
						+ "        var instance = " + fullClassName + ".$new();\n"
						: "")
				+ paramDeclarations.toString()
				+ "        " + callStatement + "\n"
				+ "        " + logStatement + "\n"
				+ (hasReturnValue ? "        return retval;\n" : "")
				+ "    });\n"
				+ "};\n";

		// 构建RPC导出函数名
		String rpcExportFunction = "call" + methodName.substring(0, 1).toUpperCase() + methodName.substring(1);
		if (methodName.equals("$init")) {
			rpcExportFunction = "callInit";
		}

		// 构建rpc.exports部分 - 直接调用 call_ 函数，避免嵌套 Java.perform
		String rpcExports = "rpc.exports = {\n"
				+ "    " + rpcExportFunction + ": function() {\n"
				+ "        return call_" + methodName + "();\n"
				+ "    }\n"
				+ "};\n\n";

		return rpcExports + functionBody;
	}


	private String generateClassSnippet(JClass jc) {
		JavaClass javaClass = jc.getCls();
		String rawClassName = StringEscapeUtils.escapeEcmaScript(javaClass.getRawName());
		// String shortClassName = javaClass.getName();
		String fullClassName = javaClass.getFullName().replace(".", "_");
		return String.format("var %s = Java.use(\"%s\");", fullClassName, rawClassName);
	}

	private String generateClassAllMethodSnippet(JClass jc, List<JavaMethod> methodList) {
		StringBuilder result = new StringBuilder();
		String classSnippet = generateClassSnippet(jc);
		result.append(classSnippet).append("\n");
		for (JavaMethod javaMethod : methodList) {
			result.append(generateMethodSnippet(javaMethod, jc)).append("\n");
		}
		return result.toString();
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

	/**
	 * 检测参数类型是否为Context或其子类
	 */
	private boolean isContextType(ArgType argType) {
		if (!argType.isObject()) {
			return false;
		}
		String typeName = argType.getObject();
		// 检查是否为Context或其常见子类
		return "android.content.Context".equals(typeName)
				|| "android.app.Application".equals(typeName)
				|| "android.app.Activity".equals(typeName)
				|| "android.app.Service".equals(typeName)
				|| "android.content.ContextWrapper".equals(typeName)
				|| typeName.endsWith("Activity")
				|| typeName.endsWith("Service")
				|| typeName.endsWith("Application");
	}
}
