using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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
using UnifiedAttestation.Core;
using UnifiedAttestation.Core.Tpm;
using UnifiedAttestation.OpcUa.RelyingParty;

namespace UnifiedAttestation.OpcUa.OnboardingApplication;

public class MockNonceProvider : INonceProvider
{
    public async Task<byte[]> GetFreshNonceAsync(CancellationToken cancellationToken = default) => [42, 43, 44, 45];
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
        Width = 500;
        Height = 300;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        KeyDown += (_, e) =>
        {
            if (e.Key == Avalonia.Input.Key.Escape)
                Close();
        };

        var text = new TextBlock
        {
            Text = $"Exception: {ex.Message}\n\n{ex.StackTrace}",
            Margin = new Thickness(10),
            TextWrapping = TextWrapping.Wrap,
        };

        var okButton = new Button
        {
            Content = "Close",
            HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Center,
            Margin = new Thickness(10),
            IsDefault = true,
        };
        okButton.Click += (_, __) => Close();

        Content = new ScrollViewer { Content = new StackPanel { Children = { text, okButton } } };
    }
}

public partial class MainWindow : Window
{
    private static readonly Regex s_hexRegex = MyRegex();

    private CancellationTokenSource _cancellationTokenSource = new();

    private readonly MockNonceProvider _nonceProvider = new();

    private readonly Dictionary<Guid, EntityAttestationData> _resultsDb = [];

    public MainWindow()
    {
        InitializeComponent();
    }

    private void BytesInput_TextChanged(object? sender, TextChangedEventArgs e)
    {
        ValidateBytesInput(SoftwareHashInput.Text ?? string.Empty);
    }

    private void ValidateBytesInput(string text)
    {
        string cleaned = text.Replace(" ", "").Replace("-", "");

        if (!s_hexRegex.IsMatch(text))
        {
            ShowError("Only hex characters (0-9, A-F) are allowed.");
            return;
        }

        if (cleaned.Length % 2 != 0)
        {
            ShowError("Hex input must contain an even number of characters.");
            return;
        }

        try
        {
            _ = ParseHexBytes(cleaned);
            ClearError();
        }
        catch
        {
            ShowError("Invalid byte sequence.");
        }
    }

    private static byte[] ParseHexBytes(string input)
    {
        byte[] bytes = new byte[input.Length / 2];

        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(input.Substring(i * 2, 2), 16);
        }

        return bytes;
    }

    private void ShowError(string message)
    {
        SoftwareHashInput.BorderBrush = Brushes.Red;
        SoftwareHashError.Text = message;
        SoftwareHashError.IsVisible = true;
    }

    private void ClearError()
    {
        SoftwareHashInput.BorderBrush = Brushes.Gray;
        SoftwareHashError.IsVisible = false;
    }

    private async void RemoteAttestationSubmit_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        SubmitAttestationButton.IsEnabled = false;
        CancelAttestationButton.IsEnabled = true;
        AttestationProgress.IsEnabled = true;
        AttestationProgress.IsVisible = true;

        AttestationDataIdInput.IsEnabled = false;
        AttesterEndpointInput.IsEnabled = false;
        VerifierEndpointInput.IsEnabled = false;

        try
        {
            if (!_cancellationTokenSource.IsCancellationRequested)
            {
                _cancellationTokenSource.Cancel();
                _cancellationTokenSource = new CancellationTokenSource();
            }

            (decimal AttestationId, string AttesterEndpoint, string VerifierEndpoint) = ReadInputs();
            (ITelemetryContext telemetry, ApplicationInstance application) = CreateApplication();
            ApplicationConfiguration config = await application.LoadApplicationConfigurationAsync(
                false,
                _cancellationTokenSource.Token
            );

            await ValidateCertificatesAsync(application);

            Dictionary<Guid, string> endpointDb = [];
            endpointDb[Guid.Empty] = AttesterEndpoint;

            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes("demo");
            IUserIdentity userIdentity = new UserIdentity("admin", passwordBytes);
            var sessionFactory = new DefaultSessionFactory(telemetry);
            var nonceProvider = new MockNonceProvider();
            var resultPolicy = new ResultAppraisalPolicy(_resultsDb);
            using OpcUaRelyingPartyClient client = new(
                sessionFactory,
                telemetry,
                userIdentity,
                endpointDb,
                VerifierEndpoint,
                config
            );
            var onboardingClient = new AttestationOrchestrator<TpmAttestationResult>(
                client,
                client,
                resultPolicy,
                nonceProvider
            );

            await onboardingClient.VerifyAsync(Guid.Empty, _cancellationTokenSource.Token);

            AttestationProgress.IsEnabled = false;
            AttestationProgress.IsVisible = false;

            UpdateResponses();

            await new SimpleMessageBox("Success", "Attestation process completed").ShowDialog(this);
        }
        catch (ServiceResultException serviceEx) when (serviceEx.Code == StatusCodes.BadRequestInterrupted)
        {
            UpdateResponses();

            AttestationProgress.IsEnabled = false;
            AttestationProgress.IsVisible = false;

            await new SimpleMessageBox("Warning", "Attestation cancelled").ShowDialog(this);
        }
        catch (Exception ex)
        {
            UpdateResponses();

            AttestationProgress.IsEnabled = false;
            AttestationProgress.IsVisible = false;

            await new ExceptionMessageBox(ex).ShowDialog(this);
        }
        finally
        {
            SubmitAttestationButton.IsEnabled = true;
            CancelAttestationButton.IsEnabled = false;
            AttestationDataIdInput.IsEnabled = true;
            AttesterEndpointInput.IsEnabled = true;
            VerifierEndpointInput.IsEnabled = true;
        }
    }

    private void UpdateResponses()
    {
        TpmAttestationResult? details = _resultsDb.GetValueOrDefault(Guid.Empty)?.Details;

        List<TpmEntryCheckViewModel> entries = details switch
        {
            null => [],

            TpmVerificationReport report => report.Entries.Select(e => new TpmEntryCheckViewModel(e)).ToList(),

            TpmNonceMismatch r => [new TpmEntryCheckViewModel(r)],
            TpmQuoteSignatureCheckFailed r => [new TpmEntryCheckViewModel(r)],
            TpmReplayFailed r => [new TpmEntryCheckViewModel(r)],

            TpmAttestationResult r => [new TpmEntryCheckViewModel(r)],
        };

        VerifierEntries.ItemsSource = entries;
    }

    private (decimal AttestationId, string AttesterEndpoint, string VerifierEndpoint) ReadInputs()
    {
        if (AttestationDataIdInput.Value is null)
            throw new InvalidOperationException("Attestation ID is missing");

        return (
            AttestationDataIdInput.Value.Value,
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
        CancelAttestationButton.IsEnabled = false;
        _cancellationTokenSource = new CancellationTokenSource();
    }

    private void SoftwareSubmit_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        string? softwareName = SoftwareNameInput.Text;
        decimal? softwareVersion = SoftwareVersionInput.Value;
        byte[]? softwareHash = null;

        if (softwareName is null || softwareVersion is null)
        {
            return;
        }

        try
        {
            softwareHash = ParseHexBytes((SoftwareHashInput.Text ?? "").Replace(" ", "").Replace("-", ""));
        }
        catch
        {
            Console.WriteLine($"Invalid Hex Provided");
        }

        Console.WriteLine($"Software Submit clicked:");
        Console.WriteLine(
            $"Name: {softwareName}, Version: {softwareVersion}, Hash: {BitConverter.ToString(softwareHash ?? [])}"
        );
    }

    [GeneratedRegex(@"^[0-9a-fA-F\s-]*$")]
    private static partial Regex MyRegex();
}
