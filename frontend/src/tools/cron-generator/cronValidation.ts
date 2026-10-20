function isDecimalDigits(value: string) {
  return value.length > 0 && !/[^0-9]/.test(value);
}

export function validateCronField(value: string, min: number, max: number, label: string) {
  // Output uses the original field, so trimming must not hide control characters.
  if (/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(value)) {
    return 'Cron schedule fields must not contain control characters or line separators.';
  }

  const trimmedValue = value.trim();

  if (!trimmedValue) {
    return `${label} is required. Use a value between ${min} and ${max}, or * for every value.`;
  }

  if (trimmedValue === '*') {
    return null;
  }

  const parts = trimmedValue.split(',');

  for (const part of parts) {
    const [rangePart, stepPart, extraStep] = part.split('/');

    if (!rangePart || extraStep !== undefined) {
      return 'Use values like *, */5, 1, 1-5, or 1-10/2.';
    }

    if (stepPart !== undefined && (!isDecimalDigits(stepPart) || !Number.isSafeInteger(Number(stepPart)) || Number(stepPart) < 1)) {
      return 'Step must be a positive safe integer (1-9007199254740991).';
    }

    if (rangePart === '*') {
      continue;
    }

    const rangeValues = rangePart.split('-');

    if (rangeValues.length > 2 || rangeValues.some((rangeValue) => !isDecimalDigits(rangeValue))) {
      return 'Use numbers, ranges, lists, wildcards, or steps.';
    }

    const start = Number(rangeValues[0]);
    const end = rangeValues.length === 2 ? Number(rangeValues[1]) : start;

    if (start < min || start > max || end < min || end > max) {
      return `Allowed range is ${min}-${max}.`;
    }

    if (start > end) {
      return 'Range start must be smaller than range end.';
    }
  }

  return null;
}
