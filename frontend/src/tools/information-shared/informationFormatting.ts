export function formatNumber(value: number, maximumFractionDigits = 2) {
  return new Intl.NumberFormat(undefined, {
    maximumFractionDigits,
  }).format(value);
}

export function parsePositiveNumber(value: string) {
  const parsedValue = Number(value);

  return value.trim() && Number.isFinite(parsedValue) && parsedValue > 0 ? parsedValue : null;
}

export function positiveProductRatio(numerators: number[], denominators: number[], ordinaryResult: number) {
  function hasSafeProduct(values: number[]) {
    let product = 1;
    return values.every((value) => {
      product *= value;
      return product >= 2 ** -1022 && Number.isFinite(product);
    });
  }

  if (ordinaryResult > 0 && Number.isFinite(ordinaryResult) &&
      hasSafeProduct(numerators) && hasSafeProduct(denominators)) {
    return ordinaryResult;
  }

  // Cancel common factors, then accumulate binary scales without overflowing intermediates.
  const remainingDenominators = [...denominators];
  const remainingNumerators = numerators.filter((value) => {
    const index = remainingDenominators.indexOf(value);
    if (index === -1) return true;
    remainingDenominators.splice(index, 1);
    return false;
  });
  let mantissa = 1;
  let exponent = 0;
  for (const [values, direction] of [[remainingNumerators, 1], [remainingDenominators, -1]] as const) {
    for (const value of values) {
      const valueExponent = Math.min(1023, Math.floor(Math.log2(value)));
      const valueMantissa = value / 2 ** valueExponent;
      mantissa = direction === 1 ? mantissa * valueMantissa : mantissa / valueMantissa;
      exponent += direction * valueExponent;
      while (mantissa >= 2) { mantissa /= 2; exponent += 1; }
      while (mantissa < 1) { mantissa *= 2; exponent -= 1; }
    }
  }

  if (exponent > 1023) return Infinity;
  // One final rounding into the subnormal range, rather than an intermediate zero.
  if (exponent < -1022) return (mantissa * 2 ** (exponent + 1074)) * Number.MIN_VALUE;
  return mantissa * 2 ** exponent;
}

export function numericRangeError(value: number) {
  if (!Number.isFinite(value)) return 'Result exceeds the supported numeric range.';
  if (value === 0) return 'Result is below the supported numeric range.';
  return '';
}

export function formatCalculatedValue(value: number, unit: string, maximumFractionDigits = 2) {
  const error = numericRangeError(value);
  return error ? `${error} (${unit})` : `${formatNumber(value, maximumFractionDigits)} ${unit}`;
}
