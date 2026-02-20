using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace UnifiedAttestation.OpcUa.OnboardingApplication;

public class BoolToColorConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not StageResult b)
        {
            return Brushes.LightGray;
        }

        return b switch
        {
            StageResult.Passed => Brushes.LightGreen,
            StageResult.Failed => Brushes.LightCoral,
            _ => Brushes.Black,
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotImplementedException();
}
