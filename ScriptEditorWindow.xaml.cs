using System.Windows;
using Wpf.Ui.Controls;

namespace SftpDeployer;

public partial class ScriptEditorWindow : FluentWindow
{
    private static readonly string DefaultYaml =
        "# 可用变量（在命令中使用 ${VAR}）：\n" +
        "#   ${FILE_LOCAL_PATH}  本地文件完整路径\n" +
        "#   ${FILE_TARGET_PATH} 配置中的目标路径\n" +
        "#   ${FILE_REMOTE_PATH} 实际上传到服务器的完整路径\n" +
        "#   ${FILE_NAME}        文件名\n" +
        "#   ${PERMISSION}       上传后要设置的权限（例如 755）\n" +
        "#   ${SERVER_ALIAS}     服务器别名\n" +
        "#   ${SERVER_HOST}      服务器地址\n" +
        "#   ${SERVER_PORT}      端口\n" +
        "#   ${SERVER_USERNAME}  用户名\n\n" +
        "before_script:\n" +
        "  - echo \"开始部署 ${FILE_NAME} 到 ${SERVER_ALIAS}\"\n\n" +
        "after_script:\n" +
        "  - echo \"完成部署 ${FILE_NAME} 到 ${SERVER_ALIAS}\"\n";

    public ScriptEditorWindow(string initialText)
    {
        InitializeComponent();
        Editor.Text = string.IsNullOrWhiteSpace(initialText) ? DefaultYaml : initialText;
    }

    public string EditedText { get; private set; } = string.Empty;

    private void OnOkClick(object sender, RoutedEventArgs e)
    {
        var text = Editor.Text ?? string.Empty;
        if (string.IsNullOrWhiteSpace(text))
        {
            // 如果用户清空了脚本，则保存为默认模板，避免运行时检测到脚本为空
            text = DefaultYaml;
            Editor.Text = text;
        }

        EditedText = text;
        DialogResult = true;
        Close();
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}