pub trait HumanReadable {
	fn bytes_as_hrb(self) -> String;
}

impl HumanReadable for u64 {
	fn bytes_as_hrb(self) -> String {
		const DIVISOR: f64 = 1000.0; //No, it's not 1024 - because we will calculate MB, not MiB. ;)
		const UNIT: [&str; 9] = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
		let mut current_multiplier = 1.0;
		let mut humanreadable_size = String::new();
		let size = self as f64;
		while (size) >= DIVISOR.powf(current_multiplier) {
			current_multiplier += 1.0;
		}
		humanreadable_size.push_str(&(format!("{:.2}", (size) / DIVISOR.powf(current_multiplier - 1.0))));
		humanreadable_size.push_str(UNIT[(current_multiplier - 1.0) as usize]);
		humanreadable_size
	}
}

pub trait GetElementByKey {
	type K;
	type V;
	fn get(&self, key: Self::K) -> Option<&Self::V>;
}

impl<K: std::cmp::PartialEq, V> GetElementByKey for Vec<(K, V)> {
	type K = K;
	type V = V;

	fn get(&self, key: K) -> Option<&V> {
		for (element_key, element_value) in self.iter() {
			if element_key == &key {
				return  Some(element_value);
			};
		}
		None
	}
}