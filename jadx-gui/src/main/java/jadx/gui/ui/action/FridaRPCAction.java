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
		if (isOverloaded(mth)) {
			String overloadArgs = methodInfo.getArgumentsTypes().stream()
					.map(this::parseArgType).collect(Collectors.joining(", "));
			overload = ".overload(" + overloadArgs + ")";
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

		// 构建参数声明部分
		StringBuilder paramDeclarations = new StringBuilder();
		if (!argVars.isEmpty()) {
			paramDeclarations.append("        // please check your args! you can hook this function to get example args\n");
			for (String argVar : argVars) {
				paramDeclarations.append("        var ").append(argVar).append(" = ?;\n");
			}
			paramDeclarations.append("\n");
		}

		// 使用三目运算符处理有无返回值的情况
		boolean hasReturnValue = !(methodInfo.isConstructor() || methodInfo.getReturnType() == ArgType.VOID);
		String callStatement = hasReturnValue
				? "var retval = " + fullClassName + "[\"" + methodName + "\"]" + overload + "(" + args + ");"
				: fullClassName + "[\"" + methodName + "\"]" + overload + "(" + args + ");";

		String logStatement = hasReturnValue
				? "console.warn(`[*] " + fullClassName + "." + methodName + " is called! \\nretval= ${retval}`);"
				: "console.warn(`[*] " + fullClassName + "." + methodName + " is called! no retval!`);";

		// 构建主动调用函数体
		String functionBody = "function call_" + methodName + "(){\n"
				+ "    Java.perform(function () {\n"
				+ "        // Smali signature: " + smaliSignature + "\n"
				+ "        " + String.format("let %s = Java.use(\"%s\");\n", fullClassName, mth.getParentClass().getFullName())
				+ (!mth.getAccessFlags().isStatic() && !methodInfo.isConstructor()
						? "        // you should hava a instance to call func\n"
						+ "        // e.g.: var instance = " + fullClassName + ".$new(?); instance.func(...);\n"
						: "")
				+ paramDeclarations.toString()
				+ "        " + callStatement + "\n"
				+ "        " + logStatement + "\n"
				+ (hasReturnValue ? "        return retval;\n" : "")
				+ "    });\n"
				+ "    console.warn(`[*] call_" + methodName + " is injected!`);\n"
				+ "};\n";

		// 构建RPC导出函数名
		String rpcExportFunction = "call" + methodName.substring(0, 1).toUpperCase() + methodName.substring(1);
		if (methodName.equals("$init")) {
			rpcExportFunction = "callInit";
		}

		// 构建rpc.exports部分 - 使用完全相同的逻辑，只是包装在rpc.exports中
		String rpcExports = "rpc.exports = {\n"
				+ "    " + rpcExportFunction + ": function() {\n"
				+ "        Java.perform(function () {\n"
				+ "            " + (hasReturnValue ? "return " : "") + "call_" + methodName + "();\n"
				+ "        });\n"
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
}
