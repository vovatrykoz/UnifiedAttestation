using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using UnifiedAttestation.OpcUa.RelyingParty;

namespace UnifiedAttestation.OpcUa.OnboardingApplication;

public class StatusToColorConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is EntityAttestationStatus status)
        {
            return status switch
            {
                EntityAttestationStatus.Passed => Brushes.LightGreen,
                EntityAttestationStatus.Failed => Brushes.LightCoral,
                EntityAttestationStatus.Unknown => Brushes.LightGray,
                _ => Brushes.White,
            };
        }

        return Brushes.White;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotImplementedException();
}
