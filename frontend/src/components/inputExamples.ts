export function clearExampleValue(value: string, example: string, setValue: (nextValue: string) => void) {
  if (value === example) {
    setValue('');
  }
}

export function restoreExampleValue(value: string, example: string, setValue: (nextValue: string) => void) {
  if (!value.trim()) {
    setValue(example);
  }
}
