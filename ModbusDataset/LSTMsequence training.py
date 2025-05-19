# import torch
# import torch.nn as nn
# import torch.optim as optim
# import numpy as np

# # Define LSTM classifier model


# class LSTMClassifier(nn.Module):
#     def __init__(self, input_size, hidden_size, num_layers, output_size):
#         super(LSTMClassifier, self).__init__()
#         self.hidden_size = hidden_size
#         self.num_layers = num_layers
#         self.lstm = nn.LSTM(input_size, hidden_size,
#                             num_layers, batch_first=True)
#         self.fc = nn.Linear(hidden_size, output_size)

#     def forward(self, x):
#         h0 = torch.zeros(self.num_layers, x.size(
#             0), self.hidden_size).to(x.device)
#         c0 = torch.zeros(self.num_layers, x.size(
#             0), self.hidden_size).to(x.device)
#         out, _ = self.lstm(x, (h0, c0))
#         out = self.fc(out[:, -1, :])
#         return out


# # Generate sample data
# # 100 sequences of length 10 with 50 features each
# X_train = np.random.rand(100, 10, 50)
# y_train = np.random.randint(2, size=(100,))  # Binary labels (0 or 1)

# # Convert data to PyTorch tensors
# X_train_tensor = torch.tensor(X_train, dtype=torch.float32)
# y_train_tensor = torch.tensor(y_train, dtype=torch.long)

# # Define model parameters
# input_size = X_train.shape[2]
# hidden_size = 64
# num_layers = 2
# output_size = 2

# # Instantiate the model
# model = LSTMClassifier(input_size, hidden_size, num_layers, output_size)

# # Define loss function and optimizer
# criterion = nn.CrossEntropyLoss()
# optimizer = optim.Adam(model.parameters(), lr=0.001)

# print(model)
# # # Train the model
# # num_epochs = 10
# # for epoch in range(num_epochs):
# #     optimizer.zero_grad()
# #     outputs = model(X_train_tensor)
# #     loss = criterion(outputs, y_train_tensor)
# #     loss.backward()
# #     optimizer.step()
# #     print(f'Epoch [{epoch+1}/{num_epochs}], Loss: {loss.item()}')

# # # Example of making predictions (not included in the final blog post)
# # X_test = np.random.rand(10, 10, 50)  # Test data with 10 sequences
# # X_test_tensor = torch.tensor(X_test, dtype=torch.float32)
# # with torch.no_grad():
# #     predictions = model(X_test_tensor)
# #     predicted_labels = torch.argmax(predictions, dim=1)
# #     print("Predicted Labels:", predicted_labels)
from sklearn.metrics import accuracy_score
from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
import numpy as np

# Generate a sample dataset with 3 classes
X, y = make_classification(n_samples=1000, n_features=20,
                           n_informative=15, n_redundant=5, n_classes=3, random_state=1)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42)

# Define and train 7 base models (replace with your GRUs in practice)
base_models = [
    LogisticRegression(random_state=0),
    SVC(probability=True, random_state=0),
    GaussianNB(),
    RandomForestClassifier(n_estimators=50, random_state=0),
    LogisticRegression(random_state=1),
    SVC(probability=True, random_state=1),
    GaussianNB()
]

# Train each base model
for model in base_models:
    model.fit(X_train, y_train)

# Get probability predictions from each base model on training data
proba_train = [model.predict_proba(X_train) for model in base_models]
X_meta_train = np.hstack(proba_train)  # Shape: (n_samples, 7 * n_classes)

# Train the random forest meta-model
meta_model = RandomForestClassifier(n_estimators=100, random_state=42)
meta_model.fit(X_meta_train, y_train)

# Get probability predictions on test data
proba_test = [model.predict_proba(X_test) for model in base_models]
X_meta_test = np.hstack(proba_test)

# Make final predictions
y_pred = meta_model.predict(X_meta_test)

# Evaluate
print(f"Accuracy of the meta-model: {accuracy_score(y_test, y_pred):.4f}")
