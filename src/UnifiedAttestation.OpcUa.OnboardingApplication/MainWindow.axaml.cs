using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Configuration;
using Opc.Ua.Gds;
using Opc.Ua.Gds.Client;
using UnifiedAttestation.Core;
using UnifiedAttestation.Core.Tpm;
using UnifiedAttestation.OpcUa.OnboardingApplication.Http;
using UnifiedAttestation.OpcUa.OnboardingApplication.OpcUa;
using UnifiedAttestation.OpcUa.RelyingParty;

namespace UnifiedAttestation.OpcUa.OnboardingApplication;

public class MockNonceProvider : INonceProvider
{
    public async Task<byte[]> GetFreshNonceAsync(CancellationToken cancellationToken = default)
    {
        byte[] bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }
}

public class CertificatePromptWindow : Window
{
    public bool IsTrusted { get; private set; } = false;

    public CertificatePromptWindow(X509Certificate2 certificate)
    {
        Title = "Untrusted Certificate Detected";
        Width = 500;
        Height = 400;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        KeyDown += (_, e) =>
        {
            if (e.Key == Avalonia.Input.Key.Escape)
                Close();
        };

        var subject = new TextBlock { Text = $"Subject: {certificate.Subject}", TextWrapping = TextWrapping.Wrap };
        var issuer = new TextBlock { Text = $"Issuer: {certificate.Issuer}", TextWrapping = TextWrapping.Wrap };
        var thumbprint = new TextBlock
        {
            Text = $"Thumbprint: {certificate.Thumbprint}",
            TextWrapping = TextWrapping.Wrap,
        };
        var validFrom = new TextBlock
        {
            Text = $"Valid From: {certificate.NotBefore}",
            TextWrapping = TextWrapping.Wrap,
        };
        var validTo = new TextBlock { Text = $"Valid To: {certificate.NotAfter}", TextWrapping = TextWrapping.Wrap };

        var stack = new StackPanel { Spacing = 8 };
        stack.Children.Add(subject);
        stack.Children.Add(issuer);
        stack.Children.Add(thumbprint);
        stack.Children.Add(validFrom);
        stack.Children.Add(validTo);

        var buttons = new StackPanel
        {
            Orientation = Avalonia.Layout.Orientation.Horizontal,
            HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Center,
            Spacing = 10,
        };
        var trustBtn = new Button { Content = "Trust" };
        var rejectBtn = new Button { Content = "Reject" };

        trustBtn.Click += (_, __) =>
        {
            IsTrusted = true;
            Close();
        };

        rejectBtn.Click += (_, __) =>
        {
            IsTrusted = false;
            Close();
        };

        buttons.Children.Add(trustBtn);
        buttons.Children.Add(rejectBtn);

        var layout = new StackPanel { Spacing = 20, Margin = new Thickness(10) };
        layout.Children.Add(
            new TextBlock
            {
                Text = "The server certificate is untrusted. Details:",
                FontWeight = Avalonia.Media.FontWeight.Bold,
            }
        );
        layout.Children.Add(stack);
        layout.Children.Add(buttons);

        Content = layout;
    }
}

public class SimpleMessageBox : Window
{
    public SimpleMessageBox(string title, string message)
    {
        Title = title;
        Width = 300;
        Height = 150;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        KeyDown += (_, e) =>
        {
            if (e.Key == Avalonia.Input.Key.Escape)
                Close();
        };

        var text = new TextBlock
        {
            Text = message,
            Margin = new Thickness(10),
            TextWrapping = TextWrapping.Wrap,
        };

        var okButton = new Button
        {
            Content = "OK",
            HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Center,
            Margin = new Thickness(10),
            IsDefault = true,
        };
        okButton.Click += (_, __) => Close();

        Content = new StackPanel { Children = { text, okButton } };
    }
}

public class ExceptionMessageBox : Window
{
    public ExceptionMessageBox(Exception ex)
    {
        Title = "Error";
        Width = 550;
        Height = 350;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        KeyDown += (_, e) =>
        {
            if (e.Key == Avalonia.Input.Key.Escape)
                Close();
        };

        var messageText = new TextBlock
        {
            Text = ex.Message + "\n" + ex.InnerException?.Message,
            FontSize = 16,
            FontWeight = FontWeight.Bold,
            TextWrapping = TextWrapping.Wrap,
        };

        var header = new Grid
        {
            ColumnDefinitions = { new ColumnDefinition(GridLength.Auto), new ColumnDefinition(GridLength.Star) },
            ColumnSpacing = 10,
        };

        header.Children.Add(
            new TextBlock
            {
                Text = "⚠",
                FontSize = 24,
                VerticalAlignment = Avalonia.Layout.VerticalAlignment.Top,
            }
        );

        Grid.SetColumn(messageText, 1);
        header.Children.Add(messageText);

        var detailsText = new TextBlock
        {
            Text = ex.StackTrace,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12,
            TextWrapping = TextWrapping.Wrap,
        };

        var expander = new Expander
        {
            Header = "Show technical details",
            Content = new ScrollViewer { Content = detailsText, MaxHeight = 150 },
        };

        var closeButton = new Button
        {
            Content = "Close",
            IsDefault = true,
            HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right,
        };
        closeButton.Click += (_, __) => Close();

        var layout = new Grid
        {
            RowDefinitions = { new RowDefinition(GridLength.Star), new RowDefinition(GridLength.Auto) },
        };

        layout.Children.Add(new StackPanel { Spacing = 10, Children = { header, expander } });

        Grid.SetRow(closeButton, 1);
        layout.Children.Add(closeButton);

        Content = new Border { Padding = new Thickness(10), Child = layout };
    }
}

public enum OnboardingStage
{
    Attestation,
    Onboarding,
    Completed,
}

public partial class MainWindow : Window
{
    private CancellationTokenSource _cancellationTokenSource = new();

    private readonly Dictionary<Guid, EntityAttestationData> _resultsDb = [];

    private readonly Dictionary<Guid, string> _endpointDb = [];

    public MainWindow()
    {
        var id = Guid.Parse("ce2104ee-6a62-4445-a1b7-a237c28df0d8");
        _resultsDb.Add(id, new EntityAttestationData("Attester", EntityAttestationStatus.Unknown, null));
        _endpointDb.Add(id, "opc.tcp://localhost:62541/");

        InitializeComponent();

        AttesterIdDropdown.SelectionChanged += (s, e) =>
        {
            if (
                AttesterIdDropdown.SelectedItem is Guid selectedGuid
                && _endpointDb.TryGetValue(selectedGuid, out string? endpoint)
            )
            {
                AttesterEndpointInput.Text = endpoint;
            }
        };

        AttesterIdDropdown.ItemsSource = _endpointDb.Keys;
        if (AttesterIdDropdown.SelectedItem is null && _endpointDb.Count > 0)
        {
            AttesterIdDropdown.SelectedIndex = 0;
        }
    }

    private async void RemoteAttestationSubmit_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        SubmitAttestationButton.IsEnabled = false;
        CancelAttestationButton.IsEnabled = true;
        AttestationProgress.IsEnabled = true;
        AttestationProgress.IsVisible = true;

        AttesterIdDropdown.IsEnabled = false;
        AttesterEndpointInput.IsEnabled = false;
        VerifierEndpointInput.IsEnabled = false;

        OnboardingStage onboardingStage = OnboardingStage.Attestation;

        (Guid id, string AttesterEndpoint, string VerifierEndpoint) = ReadInputs();

        try
        {
            if (!_cancellationTokenSource.IsCancellationRequested)
            {
                _cancellationTokenSource.Cancel();
                _cancellationTokenSource.Dispose();
                _cancellationTokenSource = new CancellationTokenSource();
            }

            _resultsDb[id] = _resultsDb[id] with { Status = EntityAttestationStatus.Unknown, Details = null };

            (ITelemetryContext telemetry, ApplicationInstance application) = CreateApplication();
            ApplicationConfiguration config = await application.LoadApplicationConfigurationAsync(
                false,
                _cancellationTokenSource.Token
            );

            List<string> temporaryTrustList = [];

            config.CertificateValidator.CertificateValidation += (s, e) =>
            {
                if (temporaryTrustList.Contains(e.Certificate.Thumbprint))
                {
                    e.Accept = true;
                    return;
                }

                if (e.Error.StatusCode == StatusCodes.BadCertificateUntrusted)
                {
                    X509Certificate2 cert = e.Certificate;

                    var tcs = new TaskCompletionSource<bool>();

                    Avalonia.Threading.Dispatcher.UIThread.Post(async () =>
                    {
                        var prompt = new CertificatePromptWindow(cert);
                        await prompt.ShowDialog(this);
                        tcs.SetResult(prompt.IsTrusted);
                    });

                    bool shouldAccept = tcs.Task.GetAwaiter().GetResult();

                    if (shouldAccept)
                    {
                        temporaryTrustList.Add(e.Certificate.Thumbprint);
                    }

                    e.Accept = shouldAccept;
                }
            };

            await ValidateCertificatesAsync(application);

            Dictionary<Guid, string> endpointDb = [];
            endpointDb[id] = AttesterEndpoint;

            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes("demo");
            IUserIdentity userIdentity = new UserIdentity("admin", passwordBytes);
            var sessionFactory = new DefaultSessionFactory(telemetry);
            var nonceProvider = new MockNonceProvider();
            var resultPolicy = new ResultAppraisalPolicy(_resultsDb);
            using OpcUaOnboardingClient attesterClient = new(
                sessionFactory,
                telemetry,
                userIdentity,
                endpointDb,
                VerifierEndpoint,
                config
            );

            using var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback =
                    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
            };
            using var httpClient = new HttpClient(handler)
            {
                BaseAddress = new Uri(VerifierEndpoint),
                Timeout = TimeSpan.FromSeconds(10),
            };

            using var verifierClient = new HttpVerifierClient(httpClient);

            var attestationOrchestrator = new AttestationOrchestrator<TpmAttestationResult>(
                attesterClient,
                verifierClient,
                resultPolicy,
                nonceProvider
            );

            await attestationOrchestrator.VerifyAsync(id, _cancellationTokenSource.Token);

            if (
                !_resultsDb.TryGetValue(id, out EntityAttestationData? entityAttestationData)
                || entityAttestationData is null
                || entityAttestationData.Status != EntityAttestationStatus.Passed
            )
            {
                UpdateResponses(id, null, onboardingStage);
                return;
            }

            onboardingStage = OnboardingStage.Onboarding;

            byte[] gdsPasswordBytes = System.Text.Encoding.UTF8.GetBytes("demo");
            IUserIdentity gdsUserIdentity = new UserIdentity("appadmin", gdsPasswordBytes);

            var gdsClient = new GdsClient(config, attesterClient, sessionFactory, endpointDb);
            await gdsClient.PerformOnboardingAsync(id, gdsUserIdentity, userIdentity);

            onboardingStage = OnboardingStage.Completed;
        }
        catch (ServiceResultException serviceEx) when (serviceEx.Code == StatusCodes.BadRequestInterrupted)
        {
            UpdateResponses(id, serviceEx, onboardingStage);

            AttestationProgress.IsEnabled = false;
            AttestationProgress.IsVisible = false;

            await new SimpleMessageBox("Warning", "Attestation cancelled").ShowDialog(this);
            return;
        }
        catch (Exception ex)
        {
            UpdateResponses(id, ex, onboardingStage);

            AttestationProgress.IsEnabled = false;
            AttestationProgress.IsVisible = false;

            await new ExceptionMessageBox(ex).ShowDialog(this);
            return;
        }
        finally
        {
            SubmitAttestationButton.IsEnabled = true;
            CancelAttestationButton.IsEnabled = false;
            AttesterIdDropdown.IsEnabled = true;
            AttesterEndpointInput.IsEnabled = true;
            VerifierEndpointInput.IsEnabled = true;
            AttestationProgress.IsEnabled = false;
            AttestationProgress.IsVisible = false;
        }

        UpdateResponses(id, null, onboardingStage);

        await new SimpleMessageBox("Success", "Attestation process completed").ShowDialog(this);
    }

    private StageResult GetStageResult(Guid id)
    {
        bool dataExists = _resultsDb.TryGetValue(id, out EntityAttestationData? data);

        if (!dataExists || data is null)
        {
            return StageResult.Unknown;
        }

        return data.Status switch
        {
            EntityAttestationStatus.Passed => StageResult.Passed,
            EntityAttestationStatus.Failed => StageResult.Failed,
            _ => StageResult.Unknown,
        };
    }

    private static StageResult GetOnboardingStageResult(OnboardingStage stage) =>
        stage switch
        {
            OnboardingStage.Completed => StageResult.Passed,
            OnboardingStage.Onboarding => StageResult.Failed,
            _ => StageResult.Unknown,
        };

    private void UpdateResponses(Guid id, Exception? ex, OnboardingStage stage)
    {
        TpmAttestationResult? details = _resultsDb.GetValueOrDefault(id)?.Details;

        StageResult stageResult = GetStageResult(id);

        var attestationStage = new StageResultViewModel
        {
            StageName = "Attestation",
            StageResult = stageResult,
            Details = details switch
            {
                null => [],
                TpmVerificationReport report => report.Entries.Select(e => new TpmEntryCheckViewModel(e)).ToList(),
                TpmNonceMismatch r => [new TpmEntryCheckViewModel(r)],
                TpmQuoteSignatureCheckFailed r => [new TpmEntryCheckViewModel(r)],
                TpmReplayFailed r => [new TpmEntryCheckViewModel(r)],
                TpmAttestationResult r => [new TpmEntryCheckViewModel(r)],
            },
            ErrorMessage = stageResult == StageResult.Passed ? null : ex?.Message,
        };

        StageResult actualStage = GetOnboardingStageResult(stage);

        var onboardingStage = new GdsResultViewModel
        {
            StageResult = actualStage,
            ErrorMessage = actualStage == StageResult.Passed ? null : ex?.Message,
        };
        StagesList.ItemsSource = new object[] { attestationStage, onboardingStage };
    }

    private (Guid AttestationId, string AttesterEndpoint, string VerifierEndpoint) ReadInputs()
    {
        if (AttesterIdDropdown.SelectedItem is null)
            throw new InvalidOperationException("Attestation ID is missing");

        return (
            (Guid)AttesterIdDropdown.SelectedItem,
            AttesterEndpointInput.Text ?? throw new InvalidOperationException("Attester endpoint missing"),
            VerifierEndpointInput.Text ?? throw new InvalidOperationException("Verifier endpoint missing")
        );
    }

    private static (ITelemetryContext Telemetry, ApplicationInstance Application) CreateApplication()
    {
        ITelemetryContext telemetry = DefaultTelemetry.Create(b => b.AddConsole());

        var application = new ApplicationInstance(telemetry)
        {
            ConfigSectionName = "AttestationClient",
            ApplicationType = ApplicationType.Client,
        };

        return (telemetry, application);
    }

    private static async Task ValidateCertificatesAsync(ApplicationInstance application)
    {
        bool certOk = await application.CheckApplicationInstanceCertificatesAsync(false);

        if (!certOk)
        {
            throw new InvalidOperationException("Client certificate check failed");
        }
    }

    private void CancelAttestation_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        _cancellationTokenSource.Cancel();
        _cancellationTokenSource.Dispose();
        _cancellationTokenSource = new CancellationTokenSource();
        CancelAttestationButton.IsEnabled = false;
    }

    private void ClearAttestationDataButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        StagesList.ItemsSource = null;
    }

    private async void GetCertificate_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        string? gdsEndpoint = GdsEndpointInput.Text;
        string? username = GdsUsernameInput.Text;
        string? password = GdsPasswordInput.Text;

        if (gdsEndpoint is null || username is null || password is null)
        {
            return;
        }

        try
        {
            byte[] gdsPasswordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            IUserIdentity gdsUserIdentity = new UserIdentity(username, gdsPasswordBytes);

            (ITelemetryContext telemetry, ApplicationInstance application) = CreateApplication();
            ApplicationConfiguration config = await application.LoadApplicationConfigurationAsync(
                false,
                _cancellationTokenSource.Token
            );
            var sessionFactory = new DefaultSessionFactory(telemetry);
            var gdsClient = new OwnGdsClient(config, sessionFactory);

            await gdsClient.GetOwnCertificateSignedAsync(gdsEndpoint, gdsUserIdentity, telemetry);
            await new SimpleMessageBox("Success", "Certificate self-update completed").ShowDialog(this);
        }
        catch (Exception ex)
        {
            await new ExceptionMessageBox(ex).ShowDialog(this);
            return;
        }
    }

    private async void ActivateGds_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        string? gdsEndpoint = GdsEndpointInput.Text;
        string? username = GdsUsernameInput.Text;
        string? password = GdsPasswordInput.Text;

        if (gdsEndpoint is null || username is null || password is null)
        {
            return;
        }

        try
        {
            byte[] gdsPasswordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            IUserIdentity gdsUserIdentity = new UserIdentity(username, gdsPasswordBytes);

            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes("demo");
            IUserIdentity userIdentity = new UserIdentity("sysadmin", gdsPasswordBytes);

            (ITelemetryContext telemetry, ApplicationInstance application) = CreateApplication();
            ApplicationConfiguration config = await application.LoadApplicationConfigurationAsync(
                false,
                _cancellationTokenSource.Token
            );
            var sessionFactory = new DefaultSessionFactory(telemetry);
            using var gdsClient = new GlobalDiscoveryServerClient(config, gdsUserIdentity, sessionFactory);
            using var client = new ServerPushConfigurationClient(config, sessionFactory)
            {
                AdminCredentials = userIdentity,
            };
            byte[] nonce = RandomNumberGenerator.GetBytes(32);

            await client.ConnectAsync("opc.tcp://localhost:58810/GlobalDiscoveryServer");

            using X509Certificate2 oldCert = X509CertificateLoader.LoadCertificate(
                client.Session.Endpoint.ServerCertificate
            );

            byte[] csr = await client.CreateSigningRequestAsync(
                client.DefaultApplicationGroup,
                client.ApplicationCertificateType,
                oldCert.SubjectName.Name,
                false,
                nonce
            );

            await gdsClient.ConnectAsync("opc.tcp://localhost:58810/GlobalDiscoveryServer");

            ApplicationDescription server = gdsClient.Session.Endpoint.Server;
            string applicationUri = gdsClient.Session.Endpoint.Server.ApplicationUri;
            string productUri = server.ProductUri;
            LocalizedText applicationName = server.ApplicationName;
            ApplicationType applicationType = server.ApplicationType;
            StringCollection discoveryUrls = server.DiscoveryUrls;

            var applicationRecord = new ApplicationRecordDataType()
            {
                ApplicationUri = applicationUri,
                ApplicationNames = [applicationName],
                ProductUri = productUri,
                ApplicationType = applicationType,
                DiscoveryUrls = discoveryUrls,
            };

            ApplicationRecordDataType[] applications = await gdsClient.FindApplicationAsync(
                "urn:abb.ab:UA:GlobalDiscoveryServer"
            );

            NodeId applicationId =
                applications.Length == 0
                    ? await gdsClient.RegisterApplicationAsync(applicationRecord)
                    : applications.First().ApplicationId;

            NodeId requestId = await gdsClient.StartSigningRequestAsync(applicationId, NodeId.Null, NodeId.Null, csr);

            (byte[] cert, byte[] _, byte[][] issuerCerts) = await gdsClient.FinishRequestAsync(
                applicationId,
                requestId
            );

            await client.ConnectAsync("opc.tcp://localhost:58810/GlobalDiscoveryServer");

            bool updateRequired = await client.UpdateCertificateAsync(
                client.DefaultApplicationGroup,
                client.ApplicationCertificateType,
                cert,
                null,
                null,
                issuerCerts
            );

            NodeId trustListId = await gdsClient.GetTrustListAsync(applicationId, NodeId.Null);
            TrustListDataType gdsTrustList = await gdsClient.ReadTrustListAsync(trustListId);
            updateRequired |= await client.UpdateTrustListAsync(gdsTrustList);

            if (updateRequired)
            {
                await client.ApplyChangesAsync();
            }
        }
        catch (Exception ex)
        {
            await new ExceptionMessageBox(ex).ShowDialog(this);
            return;
        }
    }
}
