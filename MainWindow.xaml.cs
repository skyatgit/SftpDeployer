using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using Renci.SshNet;
using Renci.SshNet.Common;
using Wpf.Ui.Controls;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using Button = System.Windows.Controls.Button;
using DataGrid = System.Windows.Controls.DataGrid;
using TextBox = System.Windows.Controls.TextBox;

namespace SftpDeployer;

public partial class MainWindow : FluentWindow, INotifyPropertyChanged
{
    // 配置持久化
    private readonly string _configDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SftpDeployer");
    private readonly string _configFile;
    private FileConfig? _homeDragItem;

    // ======= Home 文件表拖拽排序 =======
    private Point _homeDragStartPoint;
    private bool _homeIsDragging;

    private bool _isUploading;
    private CancellationTokenSource? _ctsAll;
    private CancellationTokenSource? _ctsCurrent;

    // 缓存日志区域比例，避免在无法计算时被覆盖为 null
    private double? _lastLogRatio;

    private string _logText = string.Empty;

    private FileConfig? _selectedFile;
    private bool _suspendAutoSave;

    private double _uploadProgress;

    private string _uploadStatus = string.Empty;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;

        _configFile = Path.Combine(_configDir, "config.json");
        Loaded += (_, __) => LoadConfig();
        SizeChanged += (_, __) => SaveConfig();
        StateChanged += (_, __) => SaveConfig();
        Closing += (_, __) => SaveConfig();

        // 监听集合变化以保持选择同步，并自动保存
        Servers.CollectionChanged += (s, args) =>
        {
            if (args?.NewItems != null)
                foreach (var item in args.NewItems)
                    if (item is ServerConfig sc)
                        sc.PropertyChanged += (_, __) =>
                        {
                            SaveConfig();
                            RecomputeCanUpload();
                            RefreshAllFileServerSelections();
                        };

            RefreshAllFileServerSelections();
            SaveConfig();
        };

        Files.CollectionChanged += (_, args) =>
        {
            if (args?.NewItems != null)
                foreach (var item in args.NewItems)
                    if (item is FileConfig f)
                        SubscribeFile(f);

            RecomputeCanUpload();
            SaveConfig();
        };
    }

    // 供界面绑定的集合
    public ObservableCollection<ServerConfig> Servers { get; } = new();
    public ObservableCollection<FileConfig> Files { get; } = new();

    public FileConfig? SelectedFile
    {
        get => _selectedFile;
        set
        {
            _selectedFile = value;
            OnPropertyChanged(nameof(SelectedFile));
        }
    }

    public string LogText
    {
        get => _logText;
        set
        {
            _logText = value;
            OnPropertyChanged(nameof(LogText));
        }
    }

    public double UploadProgress
    {
        get => _uploadProgress;
        set
        {
            _uploadProgress = value;
            OnPropertyChanged(nameof(UploadProgress));
        }
    }

    public string UploadStatus
    {
        get => _uploadStatus;
        set
        {
            _uploadStatus = value;
            OnPropertyChanged(nameof(UploadStatus));
        }
    }

    // 新增：当前文件进度与标签（供界面显示当前上传文件的进度）
    private double _currentFileProgress;
    public double CurrentFileProgress
    {
        get => _currentFileProgress;
        set
        {
            _currentFileProgress = value;
            OnPropertyChanged(nameof(CurrentFileProgress));
        }
    }

    private string _currentFileLabel = string.Empty;
    public string CurrentFileLabel
    {
        get => _currentFileLabel;
        set
        {
            _currentFileLabel = value;
            OnPropertyChanged(nameof(CurrentFileLabel));
        }
    }

    private string _currentFileSizeText = string.Empty;
    public string CurrentFileSizeText
    {
        get => _currentFileSizeText;
        set
        {
            _currentFileSizeText = value;
            OnPropertyChanged(nameof(CurrentFileSizeText));
        }
    }

    // 任务列表（本次上传）
    public ObservableCollection<UploadTaskItem> UploadTasks { get; } = new();

    public bool CanUpload => !_isUploading && Files.Any(f => f.IsSelected);
    public bool CanCancel => _isUploading;
    public bool IsUploading => _isUploading;
    public event PropertyChangedEventHandler? PropertyChanged;

    public class UploadTaskItem : INotifyPropertyChanged
    {
        public FileConfig File { get; set; } = null!;
        public ServerConfig Server { get; set; } = null!;

        private string _detail = string.Empty;
        public string Detail
        {
            get => _detail;
            set { _detail = value; OnPropertyChanged(nameof(Detail)); }
        }

        private string _status = string.Empty;
        public string Status
        {
            get => _status;
            set { _status = value; OnPropertyChanged(nameof(Status)); }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    private void SubscribeFile(FileConfig file)
    {
        file.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(FileConfig.IsSelected) ||
                e.PropertyName == nameof(FileConfig.TargetPath) ||
                e.PropertyName == nameof(FileConfig.Permission) ||
                e.PropertyName == nameof(FileConfig.ScriptYaml))
            {
                RecomputeCanUpload();
                SaveConfig();
            }
        };
        AttachAllowedSelectionHandlers(file);
        RebuildHomeSelections(file);
    }

    private void OnPropertyChanged(string name)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        if (name == nameof(Servers) || name == nameof(Files))
            RefreshAllFileServerSelections();
        if (name == nameof(SelectedFile))
            RecomputeCanUpload();
    }

    private void RefreshAllFileServerSelections()
    {
        foreach (var file in Files)
        {
            var existing = file.ServerSelections.ToDictionary(s => s.Alias, s => s.IsSelected);
            file.ServerSelections = new ObservableCollection<ServerSelection>(
                Servers
                    .OrderBy(s => s.Alias, StringComparer.CurrentCultureIgnoreCase)
                    .Select(s => new ServerSelection
                    {
                        Alias = s.Alias,
                        // 对已有文件，新增加的服务器默认选中（全选默认）
                        IsSelected = existing.TryGetValue(s.Alias, out var sel) ? sel : true
                    })
            );
            // 更新是否存在已选服务器
            file.HasAnyServerSelected = file.ServerSelections.Any(s => s.IsSelected);
            // 若刷新后没有任何服务器被选中，则取消勾选该文件
            if (!file.HasAnyServerSelected) file.IsSelected = false;
            AttachSelectionHandlers(file);
            // 允许列表刷新后，同步重建主页可选服务器列表
            RebuildHomeSelections(file);
        }

        RecomputeCanUpload();
    }

    private void AttachSelectionHandlers(FileConfig file)
    {
        AttachAllowedSelectionHandlers(file);
        AttachHomeSelectionHandlers(file);
    }

    private void AttachAllowedSelectionHandlers(FileConfig file)
    {
        foreach (var sel in file.ServerSelections)
            sel.PropertyChanged += (_, e) =>
            {
                if (e.PropertyName == nameof(ServerSelection.IsSelected))
                {
                    file.HasAnyServerSelected = file.ServerSelections.Any(s => s.IsSelected);
                    // 当允许列表变化时，重建主页会话选择列表
                    RebuildHomeSelections(file);
                    // 若完全不允许任何服务器，自动取消文件选择
                    if (!file.HasAnyServerSelected)
                        file.IsSelected = false;
                    RecomputeCanUpload();
                    SaveConfig(); // 仅允许列表需要持久化
                }
            };
    }

    private void AttachHomeSelectionHandlers(FileConfig file)
    {
        foreach (var sel in file.HomeServerSelections)
            sel.PropertyChanged += (_, e) =>
            {
                if (e.PropertyName == nameof(ServerSelection.IsSelected))
                {
                    file.HasAnyHomeServerSelected = file.HomeServerSelections.Any(s => s.IsSelected);
                    // 若本次上传未选择任何服务器，自动取消该文件的勾选
                    if (!file.HasAnyHomeServerSelected)
                        file.IsSelected = false;
                    RecomputeCanUpload();
                    // 保存主页选择：与文件配置页分开持久化
                    SaveConfig();
                }
            };
    }

    private void RebuildHomeSelections(FileConfig file)
    {
        // 仅包含被“允许”的服务器（allowed IsSelected=true）
        var allowed = file.ServerSelections.Where(s => s.IsSelected).ToList();
        var prev = file.HomeServerSelections?.ToDictionary(s => s.Alias, s => s.IsSelected)
                   ?? new Dictionary<string, bool>();
        file.HomeServerSelections = new ObservableCollection<ServerSelection>(
            allowed.Select(a => new ServerSelection
            {
                Alias = a.Alias,
                IsSelected = prev.TryGetValue(a.Alias, out var sel) ? sel : true
            })
        );
        file.HasAnyHomeServerSelected = file.HomeServerSelections.Any(s => s.IsSelected);
        if (!file.HasAnyHomeServerSelected)
            file.IsSelected = false;
        // 重新挂载 home 选择事件
        AttachHomeSelectionHandlers(file);
    }

    private void AppendParagraph(string text, Brush brush)
    {
        try
        {
            var run = new Run(text) { Foreground = brush };
            var p = new Paragraph(run) { Margin = new Thickness(0) };
            if (LogRichBox != null)
            {
                if (LogRichBox.Document == null)
                    LogRichBox.Document = new FlowDocument();
                LogRichBox.Document.Blocks.Add(p);
                LogRichBox.ScrollToEnd();
            }
        }
        catch
        {
        }
    }

    private void AppendLog(string message)
    {
        AppendParagraph(message, Brushes.White);
    }

    private void AppendParsedLog(string line)
    {
        if (line != null && line.StartsWith("[[CMD]]"))
        {
            var txt = line.Length > 7 ? line.Substring(7) : string.Empty;
            AppendParagraph(txt, Brushes.Green);
            return;
        }

        if (line != null && line.StartsWith("[[RES]]"))
        {
            var txt = line.Length > 7 ? line.Substring(7) : string.Empty;
            AppendParagraph(txt, Brushes.Gray);
            return;
        }

        AppendLog(line ?? string.Empty);
    }

    private void ClearLog()
    {
        try
        {
            if (LogRichBox != null)
            {
                LogRichBox.Document = new FlowDocument();
                LogRichBox.ScrollToHome();
            }

            LogText = string.Empty;
        }
        catch
        {
        }
    }

    // 按钮事件
    private void OnEditScriptClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn) return;
        if (btn.DataContext is not FileConfig fc) return;
        var win = new ScriptEditorWindow(fc.ScriptYaml) { Owner = this };
        var res = win.ShowDialog();
        if (res == true)
        {
            fc.ScriptYaml = win.EditedText;
            SaveConfig();
        }
    }

    private void OnChangeLocalFileClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn) return;
        if (btn.DataContext is not FileConfig fc) return;

        string? initialDir = null;
        try
        {
            if (!string.IsNullOrWhiteSpace(fc.LocalPath))
            {
                var dir = Path.GetDirectoryName(fc.LocalPath);
                if (!string.IsNullOrWhiteSpace(dir) && Directory.Exists(dir))
                    initialDir = dir;
            }
        }
        catch { }

        var dlg = new OpenFileDialog
        {
            Title = "选择本地文件",
            Multiselect = false
        };
        if (initialDir != null) dlg.InitialDirectory = initialDir;

        var oldFileName = System.IO.Path.GetFileName(fc.LocalPath ?? string.Empty);
        if (dlg.ShowDialog() == true)
        {
            var newPath = dlg.FileName;
            var newFileName = System.IO.Path.GetFileName(newPath);

            fc.LocalPath = newPath;

            var defaultOldTarget = "/" + (oldFileName ?? string.Empty);
            if (string.IsNullOrWhiteSpace(fc.TargetPath) || string.Equals(fc.TargetPath, defaultOldTarget, StringComparison.CurrentCultureIgnoreCase))
            {
                fc.TargetPath = "/" + newFileName;
            }
            SaveConfig();
        }
    }

    private void OnAddFileClick(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "选择要上传的文件",
            Multiselect = true
        };
        if (dlg.ShowDialog() == true)
        {
            foreach (var path in dlg.FileNames)
            {
                var file = new FileConfig
                {
                    LocalPath = path,
                    TargetPath = "/" + Path.GetFileName(path),
                    IsSelected = true
                };
                // initialize selections mirroring current servers (默认全选)
                file.ServerSelections = new ObservableCollection<ServerSelection>(
                    Servers
                        .OrderBy(s => s.Alias, StringComparer.CurrentCultureIgnoreCase)
                        .Select(s => new ServerSelection { Alias = s.Alias, IsSelected = true })
                );
                file.HasAnyServerSelected = file.ServerSelections.Any(s => s.IsSelected);
                if (!file.HasAnyServerSelected) file.IsSelected = false;
                Files.Add(file);
                SelectedFile = file;
            }

            RecomputeCanUpload();
        }
    }

    private void OnRemoveFileClick(object sender, RoutedEventArgs e)
    {
        // 仅删除文件配置页 DataGrid 中选中的行；若未选择则不删除
        var selectedItems = FilesGrid?.SelectedItems;
        if (selectedItems == null || selectedItems.Count == 0) return; // 未选择任何行，不执行删除

        // 收集要删除的 FileConfig 项
        var toRemove = new List<FileConfig>();
        foreach (var item in selectedItems)
            if (item is FileConfig fc)
                toRemove.Add(fc);
        if (toRemove.Count == 0) return;

        foreach (var f in toRemove.ToList()) Files.Remove(f);

        // 更新选中项
        SelectedFile = Files.FirstOrDefault();
        RecomputeCanUpload();
        SaveConfig();
    }

    private void OnAddServerClick(object sender, RoutedEventArgs e)
    {
        var server = new ServerConfig { Alias = $"服务器{Servers.Count + 1}", Host = "", Username = "", Password = "", Port = 22 };
        Servers.Add(server);
        RefreshAllFileServerSelections();
    }

    private void OnRemoveServerClick(object sender, RoutedEventArgs e)
    {
        // 仅删除服务器配置页 DataGrid 中选中的行；若未选择则不删除
        var selectedItems = ServersGrid?.SelectedItems;
        if (selectedItems == null || selectedItems.Count == 0) return; // 未选择任何行，不执行删除

        var toRemove = new List<ServerConfig>();
        foreach (var item in selectedItems)
            if (item is ServerConfig sc)
                toRemove.Add(sc);
        if (toRemove.Count == 0) return;

        foreach (var s in toRemove.ToList()) Servers.Remove(s);

        // 清空选择，避免自动选中最后一行
        if (ServersGrid != null) ServersGrid.SelectedIndex = -1;
        RefreshAllFileServerSelections();
        SaveConfig();
    }

    private async void OnUploadClick(object sender, RoutedEventArgs e)
    {
        _isUploading = true;
        OnPropertyChanged(nameof(CanUpload));
        OnPropertyChanged(nameof(CanCancel));
        OnPropertyChanged(nameof(IsUploading));
        UploadStatus = "正在上传...";
        UploadProgress = 0;
        ClearLog();
        _ctsAll = new CancellationTokenSource();
        _ctsCurrent = null;

        try
        {
            // 准备上传任务列表
            var jobs = (from f in Files.Where(f => f.IsSelected)
                let fileInfo = new FileInfo(f.LocalPath)
                where fileInfo.Exists
                from sel in f.HomeServerSelections.Where(s => s.IsSelected)
                join srv in Servers on sel.Alias equals srv.Alias
                select new { File = f, Server = srv, FileInfo = fileInfo }).ToList();

            if (jobs.Count == 0)
            {
                AppendLog("未选择需要上传的文件或服务器。");
                return;
            }

            // 构建任务列表到右侧表格
            UploadTasks.Clear();
            foreach (var j in jobs)
            {
                var detail = System.IO.Path.GetFileName(j.File.LocalPath) + " -> " + j.Server.Alias + " (" + j.Server.Host + "):" + j.File.TargetPath;
                UploadTasks.Add(new UploadTaskItem
                {
                    File = j.File,
                    Server = j.Server,
                    Detail = detail,
                    Status = "等待中"
                });
            }

            UploadStatus = $"已上传 0/{jobs.Count}";

            var totalBytes = jobs.Sum(j => j.FileInfo.Length);
            if (totalBytes == 0) totalBytes = 1;
            long uploadedBytes = 0;
            var successCount = 0;
            var failCount = 0;

            foreach (var job in jobs)
            {
                if (_ctsAll?.IsCancellationRequested == true)
                    break;

                var taskItem = UploadTasks.FirstOrDefault(t => ReferenceEquals(t.File, job.File) && ReferenceEquals(t.Server, job.Server));
                if (taskItem != null) taskItem.Status = "上传中";
                _ctsCurrent?.Dispose();
                _ctsCurrent = new CancellationTokenSource();
                var scriptLogs = new List<string>();
                try
                {
                    var permApplied = false;
                    string? permError = null;
                    string? appliedPermDigits = null;
                    await Task.Run(() =>
                    {
                        if (_ctsAll?.IsCancellationRequested == true) throw new OperationCanceledException("所有上传任务已取消");
                        if (_ctsCurrent?.IsCancellationRequested == true) throw new OperationCanceledException("当前文件上传已取消");
                        var remotePath = job.File.TargetPath.Replace("\\", "/");

                        // 解析脚本并准备变量
                        var (script, parseError) = TryParseScriptYaml(job.File.ScriptYaml);
                        var hasYaml = !string.IsNullOrWhiteSpace(job.File.ScriptYaml);
                        var vars = BuildScriptVariables(job.File, job.Server, remotePath);

                        var connectionInfo = new ConnectionInfo(job.Server.Host, job.Server.Port, job.Server.Username,
                            new PasswordAuthenticationMethod(job.Server.Username, job.Server.Password))
                        {
                            Encoding = Encoding.UTF8
                        };

                        using var ssh = new SshClient(connectionInfo);
                        ssh.Connect();
                        // 上传前脚本：在远程服务器上通过 SSH 执行
                        var parseErrorLogged = false;
                        if (script?.BeforeScript != null && script.BeforeScript.Count > 0)
                        {
                            if (!ExecuteStepsRemote(ssh, script.BeforeScript, vars, scriptLogs, $"[{job.Server.Alias}] [before]", line => Dispatcher.Invoke(() => AppendParsedLog(line))))
                                throw new Exception("预处理脚本失败");
                        }
                        else
                        {
                            // 未设置前置脚本时提示；若 YAML 解析失败则输出解析错误
                            if (hasYaml && !string.IsNullOrWhiteSpace(parseError))
                            {
                                Dispatcher.Invoke(() => AppendLog($"[{job.Server.Alias}] 脚本解析失败：{parseError}（不执行任何脚本）"));
                                parseErrorLogged = true;
                            }
                            else
                            {
                                Dispatcher.Invoke(() => AppendLog($"[{job.Server.Alias}] [before] 未检测到 before_script（不执行）"));
                            }
                        }

                        if (_ctsAll?.IsCancellationRequested == true) throw new OperationCanceledException("所有上传任务已取消");
                        if (_ctsCurrent?.IsCancellationRequested == true) throw new OperationCanceledException("当前文件上传已取消");

                        // 在执行 SFTP 操作前输出开始上传日志（紧跟在 before_script 之后）
                        Dispatcher.Invoke(() =>
                        {
                            AppendLog($"开始上传：{job.File.LocalPath} -> {job.Server.Alias} ({job.Server.Host}):{job.File.TargetPath}");
                            CurrentFileLabel = System.IO.Path.GetFileName(job.File.LocalPath) + " @ " + job.Server.Alias;
                            CurrentFileProgress = 0;
                            CurrentFileSizeText = $"{FormatBytes(0)} / {FormatBytes(job.FileInfo.Length)}";
                        });

                        using var sftp = new SftpClient(connectionInfo);
                        sftp.Connect();

                        // 计算本地文件哈希
                        string localHash;
                        using (var lfs = File.OpenRead(job.File.LocalPath))
                        {
                            localHash = ComputeSha256Hex(lfs);
                        }

                        // 若远端存在文件，则计算其哈希（失败则忽略，继续上传）
                        try
                        {
                            if (sftp.Exists(remotePath))
                            {
                                using var rfs = sftp.OpenRead(remotePath);
                                var remoteHash = ComputeSha256Hex(rfs);
                                if (string.Equals(localHash, remoteHash, StringComparison.OrdinalIgnoreCase))
                                {
                                    // 相同则跳过上传，但若设置了权限仍需应用
                                    if (TryParsePermissionOctal(job.File.Permission, out var mode))
                                        try
                                        {
                                            sftp.ChangePermissions(remotePath, mode);
                                            permApplied = true;
                                            appliedPermDigits = job.File.Permission;
                                        }
                                        catch (Exception exPerm)
                                        {
                                            permError = ToChineseError(exPerm);
                                        }

                                    sftp.Disconnect();

                                    // 在执行 after_script 之前，输出“已是最新”和权限结果
                                    Dispatcher.Invoke(() =>
                                    {
                                        AppendLog($"[{job.Server.Alias}] 已是最新，无需更新。");
                                        if (!string.IsNullOrWhiteSpace(job.File.Permission))
                                        {
                                            if (permApplied)
                                                AppendLog($"[{job.Server.Alias}] 已设置权限：{appliedPermDigits ?? job.File.Permission}");
                                            else if (permError != null)
                                                AppendLog($"[{job.Server.Alias}] 设置权限失败：{permError}");
                                        }
                                    });

                                    // 执行上传后脚本（即使未发生上传也执行）
                                    if (script?.AfterScript != null && script.AfterScript.Count > 0)
                                    {
                                        ExecuteStepsRemote(ssh, script.AfterScript, vars, scriptLogs, $"[{job.Server.Alias}] [after]", line => Dispatcher.Invoke(() => AppendParsedLog(line)));
                                    }
                                    else
                                    {
                                        if (hasYaml && !string.IsNullOrWhiteSpace(parseError) && !parseErrorLogged)
                                        {
                                            Dispatcher.Invoke(() => AppendLog($"[{job.Server.Alias}] 脚本解析失败：{parseError}（不执行任何脚本）"));
                                            parseErrorLogged = true;
                                        }
                                        else
                                        {
                                            Dispatcher.Invoke(() => AppendLog($"[{job.Server.Alias}] [after] 未检测到 after_script（不执行）"));
                                        }
                                    }

                                    // 跳过上传时也将当前文件进度置为100%
                                    Dispatcher.Invoke(() =>
                                    {
                                        CurrentFileProgress = 100;
                                        CurrentFileSizeText = $"{FormatBytes(job.FileInfo.Length)} / {FormatBytes(job.FileInfo.Length)}";
                                        if (taskItem != null) taskItem.Status = "成功(已是最新)";
                                    });
                                    return;
                                }
                            }
                        }
                        catch
                        {
                            // 无权限或其他原因导致读取远端文件失败，视为需要上传
                        }

                        // 需要上传时，确保目录存在
                        var remoteDir = Path.GetDirectoryName(remotePath)?.Replace("\\", "/") ?? "/";
                        CreateRemoteDirectoriesSafe(sftp, remoteDir);

                        // 使用临时文件上传，然后原子替换，避免直接覆盖失败
                        var tempPath = (remoteDir.EndsWith("/") ? remoteDir : remoteDir + "/") + ".uploading_" + Guid.NewGuid().ToString("N");
                        using (var ufs = File.OpenRead(job.File.LocalPath))
                        {
                            sftp.UploadFile(ufs, tempPath, true, uploaded =>
                            {
                                if (_ctsAll?.IsCancellationRequested == true || _ctsCurrent?.IsCancellationRequested == true)
                                {
                                    try { ufs.Close(); } catch { }
                                    return;
                                }
                                var current = uploadedBytes + (long)uploaded;
                                var percent = Math.Min(100.0, current * 100.0 / totalBytes);
                                var currentFilePercent = Math.Min(100.0, (double)uploaded * 100.0 / Math.Max(1, (double)job.FileInfo.Length));
                                Dispatcher.Invoke(() =>
                                {
                                    UploadProgress = percent;
                                    CurrentFileProgress = currentFilePercent;
                                    CurrentFileSizeText = $"{FormatBytes((long)uploaded)} / {FormatBytes(job.FileInfo.Length)}";
                                });
                            });
                        }

                        // 尝试删除旧文件后重命名临时文件为目标
                        try
                        {
                            if (sftp.Exists(remotePath))
                                try
                                {
                                    sftp.DeleteFile(remotePath);
                                }
                                catch
                                {
                                    /* 忽略删除失败，继续尝试改名覆盖 */
                                }

                            sftp.RenameFile(tempPath, remotePath);
                        }
                        catch
                        {
                            // 回退策略：若改名失败，尝试直接覆盖上传
                            using var ufs2 = File.OpenRead(job.File.LocalPath);
                            sftp.UploadFile(ufs2, remotePath, true, uploaded =>
                            {
                                if (_ctsAll?.IsCancellationRequested == true || _ctsCurrent?.IsCancellationRequested == true)
                                {
                                    try { ufs2.Close(); } catch { }
                                    return;
                                }
                                var current = uploadedBytes + (long)uploaded;
                                var percent = Math.Min(100.0, current * 100.0 / totalBytes);
                                var currentFilePercent = Math.Min(100.0, (double)uploaded * 100.0 / Math.Max(1, (double)job.FileInfo.Length));
                                Dispatcher.Invoke(() =>
                                {
                                    UploadProgress = percent;
                                    CurrentFileProgress = currentFilePercent;
                                    CurrentFileSizeText = $"{FormatBytes((long)uploaded)} / {FormatBytes(job.FileInfo.Length)}";
                                });
                            });
                            // 尝试清理临时文件
                            try
                            {
                                if (sftp.Exists(tempPath)) sftp.DeleteFile(tempPath);
                            }
                            catch
                            {
                            }
                        }

                        // 上传完成后应用权限（如果提供）
                        if (TryParsePermissionOctal(job.File.Permission, out var mode2))
                            try
                            {
                                sftp.ChangePermissions(remotePath, mode2);
                                permApplied = true;
                                appliedPermDigits = job.File.Permission;
                            }
                            catch (Exception exPerm)
                            {
                                permError = ToChineseError(exPerm);
                            }

                        sftp.Disconnect();

                        // 在执行 after_script 之前，输出“上传成功”和权限结果
                        Dispatcher.Invoke(() =>
                        {
                            AppendLog($"[{job.Server.Alias}] 上传成功。");
                            CurrentFileProgress = 100;
                            CurrentFileSizeText = $"{FormatBytes(job.FileInfo.Length)} / {FormatBytes(job.FileInfo.Length)}";
                            if (taskItem != null) taskItem.Status = "成功";
                            if (!string.IsNullOrWhiteSpace(job.File.Permission))
                            {
                                if (permApplied)
                                    AppendLog($"[{job.Server.Alias}] 已设置权限：{appliedPermDigits ?? job.File.Permission}");
                                else if (permError != null)
                                    AppendLog($"[{job.Server.Alias}] 设置权限失败：{permError}");
                            }
                        });

                        // 执行上传后脚本（远程 SSH）
                        if (script?.AfterScript != null && script.AfterScript.Count > 0)
                        {
                            ExecuteStepsRemote(ssh, script.AfterScript, vars, scriptLogs, $"[{job.Server.Alias}] [after]", line => Dispatcher.Invoke(() => AppendParsedLog(line)));
                        }
                        else
                        {
                            if (hasYaml && !string.IsNullOrWhiteSpace(parseError) && !parseErrorLogged)
                            {
                                Dispatcher.Invoke(() => AppendLog($"[{job.Server.Alias}] 脚本解析失败：{parseError}（不执行任何脚本）"));
                                parseErrorLogged = true;
                            }
                            else
                            {
                                Dispatcher.Invoke(() => AppendLog($"[{job.Server.Alias}] [after] 未检测到 after_script（不执行）"));
                            }
                        }

                        // 断开 SSH
                        try
                        {
                            ssh.Disconnect();
                        }
                        catch
                        {
                        }
                    });

                    successCount++;
                }
                catch (OperationCanceledException)
                {
                    failCount++;
                    if (taskItem != null) taskItem.Status = "已取消";
                    if (_ctsAll?.IsCancellationRequested == true)
                        AppendLog($"[{job.Server.Alias}] 已取消（已终止全部上传任务）");
                    else
                        AppendLog($"[{job.Server.Alias}] 已取消当前文件上传");
                }
                catch (Exception ex)
                {
                    failCount++;
                    if (taskItem != null) taskItem.Status = "失败";
                    if (_ctsAll?.IsCancellationRequested == true)
                        AppendLog($"[{job.Server.Alias}] 已取消（已终止全部上传任务）");
                    else if (_ctsCurrent?.IsCancellationRequested == true)
                        AppendLog($"[{job.Server.Alias}] 已取消当前文件上传");
                    else
                        AppendLog($"[{job.Server.Alias}] 上传失败：" + ToChineseError(ex));
                }
                finally
                {
                    // 即使失败也按该任务大小推进全局进度（按任务数量计）
                    uploadedBytes += job.FileInfo.Length;
                    var completedJobs = successCount + failCount;
                    UploadStatus = $"已上传 {completedJobs}/{jobs.Count}";
                    UploadProgress = Math.Min(100.0, completedJobs * 100.0 / jobs.Count);
                }
            }

            // 最终状态汇总
            if (_ctsAll?.IsCancellationRequested == true)
            {
                UploadStatus = $"已终止所有任务，已完成 {successCount}/{jobs.Count}";
            }
            else if (failCount == 0)
            {
                UploadProgress = 100;
                UploadStatus = "全部上传完成";
            }
            else if (successCount == 0)
            {
                UploadStatus = $"全部失败（0/{jobs.Count} 成功）";
            }
            else
            {
                UploadStatus = $"已完成 {successCount}/{jobs.Count}，部分失败";
            }
        }
        finally
        {
            _isUploading = false;
            OnPropertyChanged(nameof(CanUpload));
            OnPropertyChanged(nameof(CanCancel));
            OnPropertyChanged(nameof(IsUploading));
            _ctsCurrent?.Dispose();
            _ctsAll?.Dispose();
            _ctsCurrent = null;
            _ctsAll = null;
        }
    }

    private static string ToChineseError(Exception ex)
    {
        // 简单的中文错误转换/直出
        if (ex is OperationCanceledException)
            return "操作已取消";
        if (ex is SshAuthenticationException)
            return "认证失败，请检查用户名或密码。";
        if (ex is SshConnectionException)
            return "无法连接到服务器，请检查IP/主机和网络。";
        if (ex is IOException)
            return "文件读写失败，请检查本地文件路径与权限。";
        return ex.Message;
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double size = bytes;
        int unit = 0;
        while (size >= 1024 && unit < units.Length - 1)
        {
            size /= 1024;
            unit++;
        }
        return $"{size:0.##} {units[unit]}";
    }

    private static void CreateRemoteDirectoriesSafe(SftpClient sftp, string remoteDir)
    {
        if (string.IsNullOrWhiteSpace(remoteDir)) return;
        var parts = remoteDir.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
        var current = "/";
        foreach (var part in parts)
        {
            current = current.EndsWith("/") ? current + part : current + "/" + part;
            try
            {
                if (!sftp.Exists(current))
                    sftp.CreateDirectory(current);
            }
            catch
            {
                // 忽略创建目录的异常（可能已存在或无权限）
            }
        }
    }

    private void OnCancelCurrentClick(object sender, RoutedEventArgs e)
    {
        if (_isUploading)
        {
            _ctsCurrent?.Cancel();
            AppendLog("用户请求终止当前文件上传。");
        }
    }

    private void OnCancelAllClick(object sender, RoutedEventArgs e)
    {
        if (_isUploading)
        {
            _ctsAll?.Cancel();
            AppendLog("用户请求终止所有上传任务。");
        }
    }

    private async void OnRetryUploadTaskClick(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.DataContext is UploadTaskItem task)
        {
            if (_isUploading)
            {
                AppendLog("当前正在上传，请稍后再试。");
                return;
            }
            await StartSingleUploadAsync(task);
        }
    }

    private async Task StartSingleUploadAsync(UploadTaskItem taskItem)
    {
        _isUploading = true;
        OnPropertyChanged(nameof(CanUpload));
        OnPropertyChanged(nameof(CanCancel));
        OnPropertyChanged(nameof(IsUploading));
        UploadStatus = "正在上传...";
        UploadProgress = 0;
        _ctsAll = new CancellationTokenSource();
        _ctsCurrent = new CancellationTokenSource();

        try
        {
            var file = taskItem.File;
            var server = taskItem.Server;
            var fileInfo = new FileInfo(file.LocalPath);
            if (!fileInfo.Exists)
            {
                taskItem.Status = "失败(文件不存在)";
                AppendLog($"[{server.Alias}] 重传失败：本地文件不存在。");
                return;
            }

            taskItem.Status = "上传中";
            UploadStatus = "已上传 0/1";

            long totalBytes = fileInfo.Length;
            if (totalBytes == 0) totalBytes = 1;
            long uploadedBytes = 0;

            await Task.Run(() =>
            {
                if (_ctsAll?.IsCancellationRequested == true) throw new OperationCanceledException("所有上传任务已取消");
                if (_ctsCurrent?.IsCancellationRequested == true) throw new OperationCanceledException("当前文件上传已取消");

                var remotePath = file.TargetPath.Replace("\\", "/");

                var (script, parseError) = TryParseScriptYaml(file.ScriptYaml);
                var hasYaml = !string.IsNullOrWhiteSpace(file.ScriptYaml);
                var vars = BuildScriptVariables(file, server, remotePath);

                var connectionInfo = new ConnectionInfo(server.Host, server.Port, server.Username,
                    new PasswordAuthenticationMethod(server.Username, server.Password))
                {
                    Encoding = Encoding.UTF8
                };

                using var ssh = new SshClient(connectionInfo);
                ssh.Connect();

                var scriptLogs = new List<string>();
                var parseErrorLogged = false;
                if (script?.BeforeScript != null && script.BeforeScript.Count > 0)
                {
                    if (!ExecuteStepsRemote(ssh, script.BeforeScript, vars, scriptLogs, $"[{server.Alias}] [before]", line => Dispatcher.Invoke(() => AppendParsedLog(line))))
                        throw new Exception("预处理脚本失败");
                }
                else
                {
                    if (hasYaml && !string.IsNullOrWhiteSpace(parseError))
                    {
                        Dispatcher.Invoke(() => AppendLog($"[{server.Alias}] 脚本解析失败：{parseError}（不执行任何脚本）"));
                        parseErrorLogged = true;
                    }
                    else
                    {
                        Dispatcher.Invoke(() => AppendLog($"[{server.Alias}] [before] 未检测到 before_script（不执行）"));
                    }
                }

                if (_ctsAll?.IsCancellationRequested == true) throw new OperationCanceledException("所有上传任务已取消");
                if (_ctsCurrent?.IsCancellationRequested == true) throw new OperationCanceledException("当前文件上传已取消");

                Dispatcher.Invoke(() =>
                {
                    AppendLog($"开始上传：{file.LocalPath} -> {server.Alias} ({server.Host}):{file.TargetPath}");
                    CurrentFileLabel = System.IO.Path.GetFileName(file.LocalPath) + " @ " + server.Alias;
                    CurrentFileProgress = 0;
                    CurrentFileSizeText = $"{FormatBytes(0)} / {FormatBytes(fileInfo.Length)}";
                });

                using var sftp = new SftpClient(connectionInfo);
                sftp.Connect();

                string localHash;
                using (var lfs = File.OpenRead(file.LocalPath))
                {
                    localHash = ComputeSha256Hex(lfs);
                }

                try
                {
                    if (sftp.Exists(remotePath))
                    {
                        using var rfs = sftp.OpenRead(remotePath);
                        var remoteHash = ComputeSha256Hex(rfs);
                        if (string.Equals(localHash, remoteHash, StringComparison.OrdinalIgnoreCase))
                        {
                            bool permApplied = false;
                            string? permError = null;
                            string? appliedPermDigits = null;
                            if (TryParsePermissionOctal(file.Permission, out var mode))
                                try { sftp.ChangePermissions(remotePath, mode); permApplied = true; appliedPermDigits = file.Permission; }
                                catch (Exception exPerm) { permError = ToChineseError(exPerm); }

                            sftp.Disconnect();

                            Dispatcher.Invoke(() =>
                            {
                                AppendLog($"[{server.Alias}] 已是最新，无需更新。");
                                if (!string.IsNullOrWhiteSpace(file.Permission))
                                {
                                    if (permApplied) AppendLog($"[{server.Alias}] 已设置权限：{appliedPermDigits ?? file.Permission}");
                                    else if (permError != null) AppendLog($"[{server.Alias}] 设置权限失败：{permError}");
                                }

                                CurrentFileProgress = 100;
                                CurrentFileSizeText = $"{FormatBytes(fileInfo.Length)} / {FormatBytes(fileInfo.Length)}";
                                taskItem.Status = "成功(已是最新)";
                            });

                            if (script?.AfterScript != null && script.AfterScript.Count > 0)
                                ExecuteStepsRemote(ssh, script.AfterScript, vars, scriptLogs, $"[{server.Alias}] [after]", line => Dispatcher.Invoke(() => AppendParsedLog(line)));
                            else
                            {
                                if (hasYaml && !string.IsNullOrWhiteSpace(parseError) && !parseErrorLogged)
                                {
                                    Dispatcher.Invoke(() => AppendLog($"[{server.Alias}] 脚本解析失败：{parseError}（不执行任何脚本）"));
                                    parseErrorLogged = true;
                                }
                                else
                                    Dispatcher.Invoke(() => AppendLog($"[{server.Alias}] [after] 未检测到 after_script（不执行）"));
                            }

                            Dispatcher.Invoke(() => { UploadStatus = "已上传 1/1"; UploadProgress = 100; });
                            try { ssh.Disconnect(); } catch { }
                            return;
                        }
                    }
                }
                catch { }

                var remoteDir = Path.GetDirectoryName(remotePath)?.Replace("\\", "/") ?? "/";
                CreateRemoteDirectoriesSafe(sftp, remoteDir);

                var tempPath = (remoteDir.EndsWith("/") ? remoteDir : remoteDir + "/") + ".uploading_" + Guid.NewGuid().ToString("N");
                using (var ufs = File.OpenRead(file.LocalPath))
                {
                    sftp.UploadFile(ufs, tempPath, true, uploaded =>
                    {
                        if (_ctsAll?.IsCancellationRequested == true || _ctsCurrent?.IsCancellationRequested == true)
                        {
                            try { ufs.Close(); } catch { }
                            return;
                        }
                        var current = uploadedBytes + (long)uploaded;
                        var percent = Math.Min(100.0, current * 100.0 / totalBytes);
                        var currentFilePercent = Math.Min(100.0, (double)uploaded * 100.0 / Math.Max(1, (double)fileInfo.Length));
                        Dispatcher.Invoke(() =>
                        {
                            UploadProgress = percent;
                            CurrentFileProgress = currentFilePercent;
                            CurrentFileSizeText = $"{FormatBytes((long)uploaded)} / {FormatBytes(fileInfo.Length)}";
                        });
                    });
                }

                try
                {
                    if (sftp.Exists(remotePath))
                    {
                        try { sftp.DeleteFile(remotePath); } catch { }
                    }
                    sftp.RenameFile(tempPath, remotePath);
                }
                catch
                {
                    using var ufs2 = File.OpenRead(file.LocalPath);
                    sftp.UploadFile(ufs2, remotePath, true, uploaded =>
                    {
                        if (_ctsAll?.IsCancellationRequested == true || _ctsCurrent?.IsCancellationRequested == true)
                        {
                            try { ufs2.Close(); } catch { }
                            return;
                        }
                        var current = uploadedBytes + (long)uploaded;
                        var percent = Math.Min(100.0, current * 100.0 / totalBytes);
                        var currentFilePercent = Math.Min(100.0, (double)uploaded * 100.0 / Math.Max(1, (double)fileInfo.Length));
                        Dispatcher.Invoke(() =>
                        {
                            UploadProgress = percent;
                            CurrentFileProgress = currentFilePercent;
                            CurrentFileSizeText = $"{FormatBytes((long)uploaded)} / {FormatBytes(fileInfo.Length)}";
                        });
                    });
                    try { if (sftp.Exists(tempPath)) sftp.DeleteFile(tempPath); } catch { }
                }

                bool permApplied2 = false;
                string? permError2 = null;
                string? appliedPermDigits2 = null;
                if (TryParsePermissionOctal(file.Permission, out var mode2))
                    try { sftp.ChangePermissions(remotePath, mode2); permApplied2 = true; appliedPermDigits2 = file.Permission; }
                    catch (Exception exPerm) { permError2 = ToChineseError(exPerm); }

                sftp.Disconnect();

                Dispatcher.Invoke(() =>
                {
                    AppendLog($"[{server.Alias}] 上传成功。");
                    CurrentFileProgress = 100;
                    CurrentFileSizeText = $"{FormatBytes(fileInfo.Length)} / {FormatBytes(fileInfo.Length)}";
                    taskItem.Status = "成功";
                    if (!string.IsNullOrWhiteSpace(file.Permission))
                    {
                        if (permApplied2) AppendLog($"[{server.Alias}] 已设置权限：{appliedPermDigits2 ?? file.Permission}");
                        else if (permError2 != null) AppendLog($"[{server.Alias}] 设置权限失败：{permError2}");
                    }
                });

                if (script?.AfterScript != null && script.AfterScript.Count > 0)
                {
                    ExecuteStepsRemote(ssh, script.AfterScript, vars, scriptLogs, $"[{server.Alias}] [after]", line => Dispatcher.Invoke(() => AppendParsedLog(line)));
                }
                else
                {
                    if (hasYaml && !string.IsNullOrWhiteSpace(parseError) && !parseErrorLogged)
                    {
                        Dispatcher.Invoke(() => AppendLog($"[{server.Alias}] 脚本解析失败：{parseError}（不执行任何脚本）"));
                        parseErrorLogged = true;
                    }
                    else
                    {
                        Dispatcher.Invoke(() => AppendLog($"[{server.Alias}] [after] 未检测到 after_script（不执行）"));
                    }
                }

                try { ssh.Disconnect(); } catch { }

                Dispatcher.Invoke(() => { UploadStatus = "已上传 1/1"; UploadProgress = 100; });
            });
        }
        catch (OperationCanceledException)
        {
            taskItem.Status = "已取消";
            if (_ctsAll?.IsCancellationRequested == true)
                AppendLog($"[{taskItem.Server.Alias}] 已取消（已终止全部上传任务）");
            else
                AppendLog($"[{taskItem.Server.Alias}] 已取消当前文件上传");
        }
        catch (Exception ex)
        {
            taskItem.Status = "失败";
            if (_ctsAll?.IsCancellationRequested == true)
                AppendLog($"[{taskItem.Server.Alias}] 已取消（已终止全部上传任务）");
            else if (_ctsCurrent?.IsCancellationRequested == true)
                AppendLog($"[{taskItem.Server.Alias}] 已取消当前文件上传");
            else
                AppendLog($"[{taskItem.Server.Alias}] 上传失败：" + ToChineseError(ex));
        }
        finally
        {
            _isUploading = false;
            OnPropertyChanged(nameof(CanUpload));
            OnPropertyChanged(nameof(CanCancel));
            OnPropertyChanged(nameof(IsUploading));
            _ctsCurrent?.Dispose();
            _ctsAll?.Dispose();
            _ctsCurrent = null;
            _ctsAll = null;
        }
    }

    private void SaveConfig()
    {
        try
        {
            if (_suspendAutoSave) return;
            if (!IsLoaded) return;
            Directory.CreateDirectory(_configDir);

            // 计算要保存的窗口尺寸与状态
            double? saveWidth = null, saveHeight = null;
            string? saveState = null;
            if (IsLoaded)
            {
                var state = WindowState;
                saveState = state.ToString();
                if (state == WindowState.Normal)
                {
                    // 使用当前窗口宽高
                    if (!double.IsNaN(Width) && Width > 0) saveWidth = Width;
                    if (!double.IsNaN(Height) && Height > 0) saveHeight = Height;
                }
                else
                {
                    // 使用还原尺寸
                    var rb = RestoreBounds;
                    if (rb.Width > 0) saveWidth = rb.Width;
                    if (rb.Height > 0) saveHeight = rb.Height;
                }
            }

            // 计算主页日志区域比例
            double? logRatio = null;
            try
            {
                var topH = HomeTopRow?.ActualHeight ?? 0;
                var bottomH = HomeBottomRow?.ActualHeight ?? 0;
                var total = topH + bottomH;
                if (total > 1 && bottomH > 0)
                {
                    var r = bottomH / total;
                    // 合理范围裁剪，避免异常值
                    if (r > 0.03 && r < 0.97)
                    {
                        logRatio = r;
                        _lastLogRatio = r;
                    }
                }
            }
            catch
            {
            }

            if (logRatio == null && _lastLogRatio.HasValue)
                logRatio = _lastLogRatio.Value;

            // 计算右侧任务面板宽度（竖向分隔条位置）
            double? tasksPaneWidth = null;
            try
            {
                var w = TasksCol?.ActualWidth ?? 0;
                if (w > 30) tasksPaneWidth = w; // 合理最小值，避免异常
            }
            catch { }

            var data = new ConfigData
            {
                Servers = Servers.Select(s => new ServerConfig
                {
                    Alias = s.Alias,
                    Host = s.Host,
                    Username = s.Username,
                    Password = s.Password,
                    Port = s.Port
                }).ToList(),
                Files = Files.Select(f => new FileConfigDTO
                {
                    LocalPath = f.LocalPath,
                    TargetPath = f.TargetPath,
                    Permission = string.IsNullOrWhiteSpace(f.Permission) ? null : f.Permission,
                    IsSelected = f.IsSelected,
                    SelectedServerAliases = f.ServerSelections.Where(ss => ss.IsSelected).Select(ss => ss.Alias).ToList(),
                    HomeSelectedServerAliases = f.HomeServerSelections.Where(hs => hs.IsSelected).Select(hs => hs.Alias).ToList(),
                    ScriptYaml = string.IsNullOrWhiteSpace(f.ScriptYaml) ? null : f.ScriptYaml
                }).ToList(),
                WindowWidth = saveWidth,
                WindowHeight = saveHeight,
                WindowState = saveState,
                LogAreaRatio = logRatio,
                TasksPaneWidth = tasksPaneWidth
            };
            var json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
            File.WriteAllText(_configFile, json, Encoding.UTF8);
        }
        catch
        {
            // 持久化失败时忽略异常（静默处理）
        }
    }

    private void LoadConfig()
    {
        try
        {
            _suspendAutoSave = true;
            if (!File.Exists(_configFile)) return;
            var json = File.ReadAllText(_configFile, Encoding.UTF8);
            var data = JsonSerializer.Deserialize<ConfigData>(json);
            if (data == null) return;

            // 应用已保存的窗口尺寸与状态
            if (data.WindowWidth.HasValue && data.WindowWidth.Value > 100)
                Width = data.WindowWidth.Value;
            if (data.WindowHeight.HasValue && data.WindowHeight.Value > 100)
                Height = data.WindowHeight.Value;
            if (!string.IsNullOrWhiteSpace(data.WindowState) && Enum.TryParse<WindowState>(data.WindowState, out var st))
                WindowState = st;

            // 应用日志区域比例
            if (data.LogAreaRatio.HasValue)
            {
                var r = data.LogAreaRatio.Value;
                if (r > 0.03 && r < 0.97)
                {
                    HomeTopRow.Height = new GridLength(1 - r, GridUnitType.Star);
                    HomeBottomRow.Height = new GridLength(r, GridUnitType.Star);
                    _lastLogRatio = r;
                }
            }

            // 应用右侧任务面板宽度（竖向分隔条位置）
            if (data.TasksPaneWidth.HasValue && data.TasksPaneWidth.Value > 30)
            {
                TasksCol.Width = new GridLength(data.TasksPaneWidth.Value, GridUnitType.Pixel);
            }

            Servers.Clear();
            foreach (var s in data.Servers)
                Servers.Add(new ServerConfig
                {
                    Alias = s.Alias,
                    Host = s.Host,
                    Username = s.Username,
                    Password = s.Password,
                    Port = s.Port == 0 ? 22 : s.Port
                });

            Files.Clear();
            foreach (var f in data.Files)
            {
                var fc = new FileConfig
                {
                    LocalPath = f.LocalPath,
                    TargetPath = f.TargetPath,
                    Permission = f.Permission ?? string.Empty,
                    IsSelected = f.IsSelected,
                    ScriptYaml = f.ScriptYaml ?? string.Empty
                };
                var selected = new HashSet<string>(f.SelectedServerAliases ?? new List<string>());
                fc.ServerSelections = new ObservableCollection<ServerSelection>(
                    Servers
                        .OrderBy(s => s.Alias, StringComparer.CurrentCultureIgnoreCase)
                        .Select(s => new ServerSelection
                        {
                            Alias = s.Alias,
                            IsSelected = selected.Contains(s.Alias)
                        })
                );
                fc.HasAnyServerSelected = fc.ServerSelections.Any(s => s.IsSelected);

                // Restore Home (session) selections from persisted list, intersected with allowed
                var homeSaved = new HashSet<string>(f.HomeSelectedServerAliases ?? new List<string>());
                var allowed = fc.ServerSelections.Where(ss => ss.IsSelected).Select(ss => ss.Alias).ToList();
                fc.HomeServerSelections = new ObservableCollection<ServerSelection>(
                    allowed.Select(a => new ServerSelection
                    {
                        Alias = a,
                        IsSelected = homeSaved.Count == 0 ? true : homeSaved.Contains(a)
                    })
                );
                fc.HasAnyHomeServerSelected = fc.HomeServerSelections.Any(s => s.IsSelected);
                if (!fc.HasAnyHomeServerSelected)
                    fc.IsSelected = false;

                Files.Add(fc);
            }

            SelectedFile = Files.FirstOrDefault();
        }
        catch
        {
            // 加载失败时忽略异常（静默处理）
        }
        finally
        {
            _suspendAutoSave = false;
            RefreshAllFileServerSelections();
            RecomputeCanUpload();
        }
    }

    private void RecomputeCanUpload()
    {
        OnPropertyChanged(nameof(CanUpload));
    }

    private static string ComputeSha256Hex(Stream stream)
    {
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(stream);
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }

    private static bool TryParsePermissionOctal(string? text, out short mode)
    {
        // 按需求：不要进行进制转换；用户输入的数字即为实际要应用的数值。
        // 允许为空：返回 false（表示不设置权限）。
        mode = 0;
        if (string.IsNullOrWhiteSpace(text)) return false;
        var t = text.Trim();

        // 保持此前的 UI 限制：最多 3 位且每位为 0-7（UI 已限制），此处按十进制解析。
        if (!t.All(ch => ch >= '0' && ch <= '9')) return false;

        try
        {
            var val = Convert.ToInt32(t, 10);
            if (val < 0 || val > 0xFFF) return false;
            mode = (short)val;
            return true;
        }
        catch
        {
            return false;
        }
    }


    // ===== 权限输入限制：仅允许0-7三位，非法输入被拦截 =====
    private static bool IsValidPermissionDigits(string text)
    {
        if (text is null) return false;
        if (text.Length == 0) return true; // 允许为空
        foreach (var ch in text)
            if (ch < '0' || ch > '7')
                return false;
        return text.Length <= 3;
    }

    private static string ComposeNewText(TextBox tb, string incoming)
    {
        var start = tb.SelectionStart;
        var len = tb.SelectionLength;
        var current = tb.Text ?? string.Empty;
        if (start < 0 || start > current.Length) start = current.Length;
        if (len < 0 || start + len > current.Length) len = Math.Max(0, current.Length - start);
        var afterRemoval = current.Remove(start, len);
        return afterRemoval.Insert(start, incoming ?? string.Empty);
    }

    private void OnPermissionPreviewTextInput(object sender, TextCompositionEventArgs e)
    {
        if (sender is not TextBox tb) return;
        var proposed = ComposeNewText(tb, e.Text);
        if (!IsValidPermissionDigits(proposed)) e.Handled = true;
    }

    private void OnPermissionPreviewKeyDown(object sender, KeyEventArgs e)
    {
        // 允许常用控制键与导航键
        if (e.Key == Key.Back || e.Key == Key.Delete || e.Key == Key.Tab ||
            e.Key == Key.Left || e.Key == Key.Right || e.Key == Key.Home || e.Key == Key.End)
            return;
        if (e.Key == Key.Space) e.Handled = true; // 禁止空格
        // 其它按键由 PreviewTextInput 决定；此处不额外处理
    }

    private void OnPermissionPasting(object sender, DataObjectPastingEventArgs e)
    {
        if (sender is not TextBox tb) return;
        if (!e.SourceDataObject.GetDataPresent(DataFormats.UnicodeText))
        {
            e.CancelCommand();
            return;
        }

        var pasteText = e.SourceDataObject.GetData(DataFormats.UnicodeText) as string ?? string.Empty;
        var proposed = ComposeNewText(tb, pasteText);
        if (!IsValidPermissionDigits(proposed)) e.CancelCommand();
    }

    private void OnDataGridPreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (sender is not DataGrid grid) return;
        var source = e.OriginalSource as DependencyObject;
        var clickedOnRowOrCell = false;
        while (source != null)
        {
            if (source is DataGridRow || source is DataGridCell)
            {
                clickedOnRowOrCell = true;
                break;
            }

            // 若冒泡回到 DataGrid 自身则停止
            if (ReferenceEquals(source, grid)) break;
            source = VisualTreeHelper.GetParent(source);
        }

        if (!clickedOnRowOrCell)
        {
            // 先提交正在编辑的单元格/行，从而退出编辑模式
            try
            {
                grid.CommitEdit(DataGridEditingUnit.Cell, true);
                grid.CommitEdit(DataGridEditingUnit.Row, true);
            }
            catch
            {
                // 忽略提交异常，继续清理选择与焦点
            }

            grid.UnselectAll();
            grid.SelectedIndex = -1;
            // 清除焦点，避免出现编辑状态
            FocusManager.SetFocusedElement(FocusManager.GetFocusScope(grid), null);
            Keyboard.ClearFocus();
        }
    }

    // 单击“权限”单元格直接进入编辑并聚焦到 TextBox
    private void OnPermissionCellPreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (sender is not DataGridCell cell) return;
        if (cell.IsEditing) return;
        e.Handled = true;
        cell.Focus();
        var row = FindVisualParent<DataGridRow>(cell);
        if (row == null) return;
        // 选中当前行并设置当前单元格
        FilesGrid.SelectedItem = row.Item;
        FilesGrid.CurrentCell = new DataGridCellInfo(row.Item, cell.Column);
        FilesGrid.BeginEdit();
        // 聚焦到编辑框
        var tb = FindVisualChild<TextBox>(cell);
        if (tb != null)
        {
            tb.Focus();
            tb.CaretIndex = tb.Text?.Length ?? 0;
        }
    }

    private static T? FindVisualParent<T>(DependencyObject? child) where T : DependencyObject
    {
        if (child == null) return null;
        var parent = VisualTreeHelper.GetParent(child);
        while (parent != null)
        {
            if (parent is T t) return t;
            parent = VisualTreeHelper.GetParent(parent);
        }

        return null;
    }

    private static T? FindVisualChild<T>(DependencyObject parent) where T : DependencyObject
    {
        if (parent == null) return null;
        var count = VisualTreeHelper.GetChildrenCount(parent);
        for (var i = 0; i < count; i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T tChild) return tChild;
            var result = FindVisualChild<T>(child);
            if (result != null) return result;
        }

        return null;
    }

    private void OnPermissionLostFocus(object sender, RoutedEventArgs e)
    {
        if (sender is not TextBox tb) return;
        var t = tb.Text?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(t))
        {
            // keep empty as-is
            if (tb.DataContext is FileConfig fcEmpty && fcEmpty.Permission != string.Empty)
                fcEmpty.Permission = string.Empty;
            return;
        }

        // pad to length 3 with trailing zeros
        var normalized = t.PadRight(3, '0');
        if (tb.Text != normalized)
            tb.Text = normalized;
        if (tb.DataContext is FileConfig fc && fc.Permission != normalized)
            fc.Permission = normalized;
    }

    private void OnHomeSplitterDragCompleted(object sender, DragCompletedEventArgs e)
    {
        // 用户拖拽完成时保存当前日志区域高度比例
        SaveConfig();
    }

    private void OnHomeFilesPreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (sender is not DataGrid grid) return;
        _homeDragStartPoint = e.GetPosition(grid);

        // 避免在点击交互控件时触发拖拽（如 CheckBox）
        var src = e.OriginalSource as DependencyObject;
        if (FindVisualParent<ToggleButton>(src) != null ||
            FindVisualParent<ButtonBase>(src) != null)
        {
            _homeDragItem = null;
            _homeIsDragging = false;
            return;
        }

        var row = FindVisualParent<DataGridRow>(src);
        _homeDragItem = row?.Item as FileConfig;
        _homeIsDragging = false;
    }

    private void OnHomeFilesMouseMove(object sender, MouseEventArgs e)
    {
        if (sender is not DataGrid grid) return;
        if (e.LeftButton != MouseButtonState.Pressed) return;
        if (_homeDragItem == null) return;

        var pos = e.GetPosition(grid);
        if (Math.Abs(pos.X - _homeDragStartPoint.X) < SystemParameters.MinimumHorizontalDragDistance &&
            Math.Abs(pos.Y - _homeDragStartPoint.Y) < SystemParameters.MinimumVerticalDragDistance)
            return;

        _homeIsDragging = true;
        try
        {
            DragDrop.DoDragDrop(grid, _homeDragItem, DragDropEffects.Move);
        }
        finally
        {
            _homeIsDragging = false;
        }
    }

    private void OnHomeFilesDragOver(object sender, DragEventArgs e)
    {
        if (_homeIsDragging && e.Data.GetDataPresent(typeof(FileConfig)))
        {
            e.Effects = DragDropEffects.Move;
            e.Handled = true;
        }
        else
        {
            e.Effects = DragDropEffects.None;
        }
    }

    private void OnHomeFilesDrop(object sender, DragEventArgs e)
    {
        if (sender is not DataGrid grid) return;
        if (!e.Data.GetDataPresent(typeof(FileConfig))) return;
        var draggedItem = (FileConfig?)e.Data.GetData(typeof(FileConfig));
        if (draggedItem == null) return;

        // 计算目标索引
        var target = GetItemAtPosition<FileConfig>(grid, e.GetPosition(grid));
        var oldIndex = Files.IndexOf(draggedItem);
        var newIndex = target != null ? Files.IndexOf(target) : Files.Count - 1;
        if (oldIndex < 0) return;
        if (newIndex < 0) newIndex = Files.Count - 1;
        if (newIndex >= Files.Count) newIndex = Files.Count - 1;

        if (newIndex != oldIndex)
        {
            Files.Move(oldIndex, newIndex);
            SelectedFile = draggedItem;
            SaveConfig();
        }

        _homeDragItem = null;
        _homeIsDragging = false;
    }

    private static TItem? GetItemAtPosition<TItem>(DataGrid grid, Point position) where TItem : class
    {
        var hit = VisualTreeHelper.HitTest(grid, position);
        if (hit == null) return null;
        var d = hit.VisualHit;
        var row = FindVisualParent<DataGridRow>(d);
        return row?.Item as TItem;
    }

    private static FileScript? ParseScriptYaml(string? yaml)
    {
        if (string.IsNullOrWhiteSpace(yaml)) return null;
        try
        {
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(UnderscoredNamingConvention.Instance)
                .IgnoreUnmatchedProperties()
                .Build();
            var script = deserializer.Deserialize<FileScript>(yaml);
            return script;
        }
        catch
        {
            return null;
        }
    }

    private static (FileScript? script, string? error) TryParseScriptYaml(string? yaml)
    {
        if (string.IsNullOrWhiteSpace(yaml)) return (null, null);
        try
        {
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(UnderscoredNamingConvention.Instance)
                .IgnoreUnmatchedProperties()
                .Build();
            var script = deserializer.Deserialize<FileScript>(yaml);
            return (script, null);
        }
        catch (Exception ex)
        {
            return (null, ex.Message);
        }
    }

    private static Dictionary<string, string> BuildScriptVariables(FileConfig file, ServerConfig server, string remotePath)
    {
        var dict = new Dictionary<string, string>
        {
            ["FILE_LOCAL_PATH"] = file.LocalPath ?? string.Empty,
            ["FILE_TARGET_PATH"] = file.TargetPath ?? string.Empty,
            ["FILE_REMOTE_PATH"] = remotePath ?? string.Empty,
            ["FILE_NAME"] = Path.GetFileName(file.LocalPath ?? string.Empty) ?? string.Empty,
            ["PERMISSION"] = file.Permission ?? string.Empty,
            ["SERVER_ALIAS"] = server.Alias ?? string.Empty,
            ["SERVER_HOST"] = server.Host ?? string.Empty,
            ["SERVER_PORT"] = server.Port.ToString(),
            ["SERVER_USERNAME"] = server.Username ?? string.Empty
        };
        return dict;
    }

    private static string ExpandVariables(string input, Dictionary<string, string> vars)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        var sb = new StringBuilder();
        for (var i = 0; i < input.Length; i++)
        {
            if (i + 2 < input.Length && input[i] == '$' && input[i + 1] == '{')
            {
                var end = input.IndexOf('}', i + 2);
                if (end > i + 2)
                {
                    var key = input.Substring(i + 2, end - (i + 2));
                    if (vars.TryGetValue(key, out var val)) sb.Append(val);
                    else sb.Append("${" + key + "}");
                    i = end;
                    continue;
                }
            }

            sb.Append(input[i]);
        }

        return sb.ToString();
    }

    private static (bool success, string output) ExecutePowerShellStep(string command, Dictionary<string, string> vars, string? workingDir)
    {
        // 保留以备未来可能的本地脚本使用，但当前需求使用 SSH 远程执行
        try
        {
            var baseDir = Path.Combine(Path.GetTempPath(), "SftpDeployer");
            Directory.CreateDirectory(baseDir);
            var tempPath = Path.Combine(baseDir, Guid.NewGuid().ToString("N") + ".ps1");
            var expanded = ExpandVariables(command, vars);
            File.WriteAllText(tempPath, expanded, Encoding.UTF8);

            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{tempPath}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            if (!string.IsNullOrWhiteSpace(workingDir) && Directory.Exists(workingDir))
                psi.WorkingDirectory = workingDir!;
            foreach (var kv in vars)
                psi.Environment[kv.Key] = kv.Value ?? string.Empty;

            using var proc = Process.Start(psi)!;
            var stdout = proc.StandardOutput.ReadToEnd();
            var stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit();
            var code = proc.ExitCode;
            try
            {
                File.Delete(tempPath);
            }
            catch
            {
            }

            var output = string.Join(Environment.NewLine, new[] { stdout, stderr }.Where(s => !string.IsNullOrEmpty(s)).Select(s => s.TrimEnd()));
            return (code == 0, output);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    private static bool ExecuteSteps(IEnumerable<string> steps, Dictionary<string, string> vars, string? workingDir, List<string> logs, string prefix)
    {
        // 已不用于远程执行，保留向后兼容
        var ok = true;
        var idx = 1;
        foreach (var raw in steps)
        {
            var step = raw ?? string.Empty;
            if (string.IsNullOrWhiteSpace(step))
            {
                idx++;
                continue;
            }

            var (success, output) = ExecutePowerShellStep(step, vars, workingDir);
            if (!string.IsNullOrWhiteSpace(output))
                foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                    logs.Add($"{prefix} {line}");
            if (!success)
            {
                logs.Add($"{prefix} 命令失败（第{idx}步）");
                ok = false;
                break;
            }

            idx++;
        }

        return ok;
    }

    private static (bool success, string output) ExecuteSshStep(SshClient ssh, string command, Dictionary<string, string> vars)
    {
        try
        {
            var expanded = ExpandVariables(command, vars);
            var cmd = ssh.CreateCommand(expanded);
            // Use a sane timeout to prevent hanging forever
            cmd.CommandTimeout = TimeSpan.FromMinutes(10);
            // Execute synchronously so SSH.NET drains output internally
            var stdout = cmd.Execute(); // this returns the Result
            var stderr = cmd.Error ?? string.Empty;
            stdout ??= string.Empty;
            var output = string.Join(Environment.NewLine, new[] { stdout, stderr }
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.TrimEnd()));
            return (cmd.ExitStatus == 0, output);
        }
        catch (SshOperationTimeoutException)
        {
            return (false, "SSH 命令执行超时");
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    private static bool ExecuteStepsRemote(SshClient ssh, IEnumerable<string> steps, Dictionary<string, string> vars, List<string> logs, string prefix, Action<string>? onLog = null)
    {
        void Emit(string line)
        {
            logs.Add(line);
            try
            {
                onLog?.Invoke(line);
            }
            catch
            {
            }
        }

        var list = steps?.ToList() ?? new List<string>();
        var ok = true;
        foreach (var raw in list)
        {
            var step = raw ?? string.Empty;
            if (string.IsNullOrWhiteSpace(step)) continue;
            var (success, output) = ExecuteSshStep(ssh, step, vars);
            var result = output?.Replace("\r", " ").Replace("\n", " ")?.Trim();
            if (string.IsNullOrWhiteSpace(result)) result = string.Empty;

            // 原始命令（绿色，一行）
            var cmdLine = string.IsNullOrWhiteSpace(prefix) ? step : $"{prefix} {step}";
            Emit("[[CMD]]" + cmdLine);
            // 执行结果（灰色，一行）
            var resLine = string.IsNullOrWhiteSpace(prefix) ? result : $"{prefix} {result}";
            Emit("[[RES]]" + resLine);

            if (!success)
            {
                ok = false;
                break;
            }
        }

        return ok;
    }

    // ===== 脚本解析与执行 =====
    private class FileScript
    {
        public List<string>? BeforeScript { get; set; }
        public List<string>? AfterScript { get; set; }
    }

    // 数据模型
    public class ServerConfig : INotifyPropertyChanged
    {
        private string _alias = string.Empty;
        private string _host = string.Empty;
        private string _password = string.Empty;
        private int _port = 22;
        private string _username = string.Empty;

        public string Alias
        {
            get => _alias;
            set
            {
                _alias = value;
                OnPropertyChanged(nameof(Alias));
            }
        }

        public string Host
        {
            get => _host;
            set
            {
                _host = value;
                OnPropertyChanged(nameof(Host));
            }
        }

        public int Port
        {
            get => _port;
            set
            {
                _port = value;
                OnPropertyChanged(nameof(Port));
            }
        }

        public string Username
        {
            get => _username;
            set
            {
                _username = value;
                OnPropertyChanged(nameof(Username));
            }
        }

        public string Password
        {
            get => _password;
            set
            {
                _password = value;
                OnPropertyChanged(nameof(Password));
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected void OnPropertyChanged(string name)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }

        public bool IsValid()
        {
            return !string.IsNullOrWhiteSpace(Alias) && !string.IsNullOrWhiteSpace(Host) && !string.IsNullOrWhiteSpace(Username);
        }
    }

    public class ServerSelection : INotifyPropertyChanged
    {
        private bool _isSelected;
        public string Alias { get; set; } = string.Empty;

        public bool IsSelected
        {
            get => _isSelected;
            set
            {
                _isSelected = value;
                OnPropertyChanged(nameof(IsSelected));
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected void OnPropertyChanged(string name)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }

    public class FileConfig : INotifyPropertyChanged
    {
        private bool _hasAnyHomeServerSelected;
        private bool _hasAnyServerSelected;

        // 主页会话内的服务器选择（仅显示“允许上传”的服务器子集）
        private ObservableCollection<ServerSelection> _homeServerSelections = new();
        private bool _isSelected;
        private string _localPath = string.Empty;
        private string _permission = string.Empty;
        private string _scriptYaml = string.Empty;
        private ObservableCollection<ServerSelection> _serverSelections = new();
        private string _targetPath = string.Empty;

        public string LocalPath
        {
            get => _localPath;
            set
            {
                _localPath = value;
                OnPropertyChanged(nameof(LocalPath));
            }
        }

        public string TargetPath
        {
            get => _targetPath;
            set
            {
                _targetPath = value;
                OnPropertyChanged(nameof(TargetPath));
            }
        }

        public bool IsSelected
        {
            get => _isSelected;
            set
            {
                _isSelected = value;
                OnPropertyChanged(nameof(IsSelected));
            }
        }

        public ObservableCollection<ServerSelection> ServerSelections
        {
            get => _serverSelections;
            set
            {
                _serverSelections = value;
                OnPropertyChanged(nameof(ServerSelections));
            }
        }

        public ObservableCollection<ServerSelection> HomeServerSelections
        {
            get => _homeServerSelections;
            set
            {
                _homeServerSelections = value;
                OnPropertyChanged(nameof(HomeServerSelections));
            }
        }

        public string Permission
        {
            get => _permission;
            set
            {
                _permission = value;
                OnPropertyChanged(nameof(Permission));
            }
        }

        public string ScriptYaml
        {
            get => _scriptYaml;
            set
            {
                _scriptYaml = value ?? string.Empty;
                OnPropertyChanged(nameof(ScriptYaml));
            }
        }

        public bool HasAnyServerSelected
        {
            get => _hasAnyServerSelected;
            set
            {
                _hasAnyServerSelected = value;
                OnPropertyChanged(nameof(HasAnyServerSelected));
            }
        }

        public bool HasAnyHomeServerSelected
        {
            get => _hasAnyHomeServerSelected;
            set
            {
                _hasAnyHomeServerSelected = value;
                OnPropertyChanged(nameof(HasAnyHomeServerSelected));
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected void OnPropertyChanged(string name)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }

    // ===================== Persistence =====================
    private class FileConfigDTO
    {
        public string LocalPath { get; set; } = string.Empty;
        public string TargetPath { get; set; } = string.Empty;
        public string? Permission { get; set; }
        public bool IsSelected { get; set; }
        public List<string> SelectedServerAliases { get; set; } = new();
        public List<string> HomeSelectedServerAliases { get; set; } = new();
        public string? ScriptYaml { get; set; }
    }

    private class ConfigData
    {
        public List<ServerConfig> Servers { get; set; } = new();
        public List<FileConfigDTO> Files { get; set; } = new();
        public double? WindowWidth { get; set; }
        public double? WindowHeight { get; set; }
        public string? WindowState { get; set; }
        public double? LogAreaRatio { get; set; }
        public double? TasksPaneWidth { get; set; }
    }
}