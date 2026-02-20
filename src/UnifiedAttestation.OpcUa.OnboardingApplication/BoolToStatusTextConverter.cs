using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace UnifiedAttestation.OpcUa.OnboardingApplication;

public class BoolToStatusTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not StageResult b)
        {
            return "Unknown";
        }

        return b switch
        {
            StageResult.Passed => "Passed",
            StageResult.Failed => "Failed",
            _ => "Unknown",
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotImplementedException();
}
